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

def get_project(pid):
    """
    Get a project database using the pid.
    """

    pdb = database.ProjectDatabase()
    project = pdb.get_project(pid)

    if project is None:
        return flask.redirect(flask.url_for('projects'))

    else:
        return project


@app.route("/")
def index():
    return flask.render_template('index.html')


@app.route("/about")
def about():
    return flask.render_template('about.html')


@app.route('/project/<pid>/host/<ip>')
def host(pid, ip):
    """
    Get all the information about a host.
    """
    project = get_project(pid)

    db = database.ScanDatabase(project['dbfile'])
    data = db.get_host(ip)

    if data is None:
        flask.abort(404)

    return flask.render_template('host.html', host=ip, data=data)


@app.route('/project/<pid>/item/<item_id>')
def item(pid, item_id):
    """
    Get all the information about an item.
    """
    project = get_project(pid)

    db = database.ScanDatabase(project['dbfile'])
    item = db.get_item(item_id)

    if item is None:
        flask.abort(404)

    return flask.render_template('item.html', item=item)

@app.route('/project/<pid>/attack/<aid>', methods=['GET', 'POST'])
def get_attack(pid, aid):
    """
    Get list of all the hosts possibly vulnerable to the attack.
    """
    project = get_project(pid)
    db = database.ScanDatabase(project['dbfile'])

    if flask.request.method == 'POST':
        note = flask.request.form['note']
        db.update_attack_note(aid, note)

    attack = db.get_attack(aid)

    if attack is None:
        flask.abort(404)

    items = [i.split(':') for i in attack['items'].split(',')]

    return flask.render_template('attack.html', attack=attack, items=items, pid=pid)


@app.route('/project/<pid>/import', methods=['GET', 'POST'])
def import_scan(pid):
    """
    Import scan data into the database associated with the pid.
    """

    if flask.request.method == 'GET':
        return flask.render_template('import.html', pid=pid)

    else:
        project = get_project(pid)

        i = importscan.Import(project['dbfile'])
        scans = flask.request.files.getlist("scans[]")

        for scan in scans:
            i.import_scan(scan.read())

        a = attacks.Attack(project['dbfile'])
        a.find_attacks()

        return flask.redirect(flask.url_for('project', pid=pid))


@app.route('/project/<pid>/notes')
def notes(pid):
    """
    Display all attack notes.
    """
    project = get_project(pid)

    db = database.ScanDatabase(project['dbfile'])
    notes = db.get_attack_notes()

    return flask.render_template('notes.html', notes=notes)


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

    projects = pdb.get_projects()
    for project in projects:
        db = database.ScanDatabase(project['dbfile'])
        stats[project['id']] = db.get_stats() 

    return flask.render_template('projects.html', projects=projects, stats=stats)


@app.route('/project/<pid>')
def project(pid):
    """
    Get a project, including the list of hosts attacks.
    """
    project = get_project(pid)

    ports = {}

    db = database.ScanDatabase(project['dbfile'])
    hosts = db.get_hosts()
    attacks = db.get_attacks()

    for host in hosts:
        ip = host['ip']
        port_list = db.get_ports(ip)
        ports[ip] = [str(p['port']) for p in port_list if p['port'] != 0]

    return flask.render_template('project.html', pid=pid,
                                 project=project['name'], hosts=hosts,
                                 ports=ports, attacks=attacks)


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
