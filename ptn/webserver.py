# -*- coding: utf-8 -*-

import flask
from functools import wraps
import logging

import database
import importscan
import attacks


#-----------------------------------------------------------------------------
# WEB SERVER
#-----------------------------------------------------------------------------
app = flask.Flask(__name__)

def ip_key(ip):
    return tuple(int(part) for part in ip.split('.'))

def get_project_db(pid):
    """
    Get our project database.
    """
    pdb = database.ProjectDatabase()
    project = pdb.get_project(pid)

    if project is None:
        flask.abort(404)

    return project


@app.route("/")
def index():
    return flask.render_template('index.html')


@app.route("/about")
def about():
    return flask.render_template('about.html')


@app.route("/project/<pid>/hosts")
def hosts(pid):
    """
    Get summary inforation about all imported hosts.
    """
    project = get_project_db(pid)
    db = database.ScanDatabase(project['dbfile'])

    summary = db.itemdb.get_summary()
    hosts = {}
    ips = sorted(summary['ips'], key=lambda x: ip_key(x[0]))
    tcp = [str(p) for p in summary['tcp']]
    udp = [str(p) for p in summary['udp']]

    for host in summary['hosts']:
        ip = host['ip']
        port = host['port']
        proto = host['protocol']

        if ip not in hosts:
            hosts[ip] = {'tcp': [], 'udp': []}

        if host['protocol'] == 'tcp':
            hosts[ip]['tcp'].append(port)
        elif host['protocol'] == 'udp':
            hosts[ip]['udp'].append(port)
        else:
            pass

    for host in hosts:
        hosts[host]['tcp'] = [str(t) for t in sorted(set(hosts[host]['tcp']))]
        hosts[host]['udp'] = [str(t) for t in sorted(set(hosts[host]['udp']))]

    return flask.render_template('hosts.html', pid=pid, name=project['name'],
                                 hosts=hosts, ips=ips, tcp=tcp, udp=udp)


@app.route('/project/<pid>/host/<ip>', methods=['GET', 'POST'])
def host(pid, ip):
    """
    Get all the information about a host.
    """
    project = get_project_db(pid)
    db = database.ScanDatabase(project['dbfile'])

    if flask.request.method == 'POST':
        note = flask.request.form['note']
        db.hostdb.update_host_note(ip, note)

    data = db.get_host_details(ip)

    if data is None:
        flask.abort(404)

    details = {}
    for item in data['items']:
        key = "{0}/{1}".format(item['port'], item['protocol'])
        if details.get(key) is None:
            details[key] = []
            details[key].append(item['note'])
        else:
            details[key].append(item['note'])

    keys = sorted(details.keys(), key=lambda x: int(x.split('/')[0]))
    note = data['note']

    return flask.render_template('host.html', pid=pid, host=ip,
            details=details, keys=keys, note=note,
            name=project['name'])


@app.route('/project/<pid>/host/notes')
def host_notes(pid):
    """
    Display all host notes.
    """
    project = get_project_db(pid)
    db = database.ScanDatabase(project['dbfile'])
    notes = db.hostdb.get_host_notes()

    return flask.render_template('notes.html', pid=pid, notes=notes,
                name=project['name'])


@app.route('/project/<pid>/item/<item_id>')
def item(pid, item_id):
    """
    Get all the information about an item.
    """
    project = get_project_db(pid)
    db = database.ScanDatabase(project['dbfile'])
    item = db.itemdb.get_item(item_id)

    if item is None:
        flask.abort(404)

    return flask.render_template('item.html', pid=pid, item=item,
                name=project['name'])


@app.route('/project/<pid>/attack/<aid>', methods=['GET', 'POST'])
def get_attack(pid, aid):
    """
    Get list of all the hosts possibly vulnerable to the attack.
    """
    project = get_project_db(pid)
    db = database.ScanDatabase(project['dbfile'])

    if flask.request.method == 'POST':
        note = flask.request.form['note']
        db.attackdb.update_attack_note(aid, note)

    attack = db.attackdb.get_attack(aid)

    if attack is None:
        flask.abort(404)

    items = [i.split(':') for i in set(attack['items'].split(','))]

    return flask.render_template('attack.html', pid=pid, attack=attack,
                items=items, name=project['name'])


@app.route('/project/<pid>/import', methods=['GET', 'POST'])
def import_scan(pid):
    """
    Import scan data into the database associated with the pid.
    """
    project = get_project_db(pid)
    db = database.ScanDatabase(project['dbfile'])

    if flask.request.method == 'GET':
        files = db.importdb.get_imported_files()

        return flask.render_template('import.html', pid=pid, files=files,
                    name=project['name'])

    else:
        i = importscan.Import(project['dbfile'])
        scans = flask.request.files.getlist("scans[]")

        for scan in scans:
            res = i.import_scan(scan.read())
            if res is True:
                db.importdb.add_import_file(scan.filename)

        a = attacks.Attack(project['dbfile'])
        a.find_attacks()

        return flask.redirect(flask.url_for('get_project', pid=pid))


@app.route('/project/<pid>/attack/notes')
def attack_notes(pid):
    """
    Display all attack notes.
    """
    project = get_project_db(pid)
    db = database.ScanDatabase(project['dbfile'])
    notes = db.attackdb.get_attack_notes()

    return flask.render_template('notes.html', pid=pid, notes=notes,
                name=project['name'])


@app.route('/projects', methods=['GET', 'POST'])
def projects():
    """
    Get a list of all projects.
    """
    pdb = database.ProjectDatabase()
    stats = {}

    if flask.request.method == 'POST':
        name = flask.request.form['project_name']
        pdb.create_project(name)

    project_list = pdb.get_projects()
    for project in project_list:
        db = database.ScanDatabase(project['dbfile'])
        stats[project['id']] = db.get_stats()

    return flask.render_template('projects.html', projects=project_list, stats=stats)


@app.route('/project/<pid>')
def get_project(pid):
    """
    Get a project, including the list of hosts attacks.
    """
    project = get_project_db(pid)

    db = database.ScanDatabase(project['dbfile'])
    attacks = db.attackdb.get_attacks()

    return flask.render_template('project.html', pid=pid, note=project['note'],
                                 name=project['name'], attacks=attacks)


@app.route('/project/<pid>/notes', methods=['GET', 'POST'])
def project_notes(pid):
    """
    Display all project notes.
    """
    pdb = database.ProjectDatabase()
    project = get_project_db(pid)

    if flask.request.method == 'POST':
        note = flask.request.form['note']
        pdb.update_project_note(pid, note)

        return flask.redirect(flask.url_for('get_project', pid=pid))
    else:
        return flask.render_template('project_notes.html', pid=pid,
                    name=project['name'], note=project['note'])

@app.route('/project/<pid>/delete')
def delete_project(pid):
    """
    Delete the specified project.
    """
    pdb = database.ProjectDatabase()
    project = pdb.delete_project(pid)

    return flask.redirect(flask.url_for('projects'))


@app.errorhandler(404)
def page_not_found(e):
    return flask.render_template('404.html'), 404


@app.errorhandler(500)
def inernal_error(e):
    return flask.render_template('500.html'), 500
