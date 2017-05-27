# pip install flask


from flask import Flask
from flask import Flask, request, session, g, redirect, url_for, abort, render_template, flash
import sqlite3 as sql
import json

app = Flask(__name__)


def insert_computer(computer_name, user_name, password):
	return_value = "0"
	con = sql.connect("db.db")
	cur = con.cursor()
	cur.execute("SELECT * FROM computer where computer_name = ? and user_name = ?", (computer_name, user_name))
	user = cur.fetchone()
	
	if user == None:		
		cur.execute("INSERT INTO computer (computer_name, user_name, password, date) VALUES (?, ?, ?, CURRENT_TIMESTAMP)", (computer_name, user_name, password))
		con.commit()
		return_value = "1"
	
	con.close()
	return return_value
	
	
@app.route('/list', methods=['GET'])
def list():
	if session.get('logged_in') != True or session['logged_in'] != True:
		return redirect(url_for('login'))
		
	con = sql.connect("db.db")
	cur = con.cursor()
	cur.execute("SELECT * FROM computer ")
	all = cur.fetchall()
	con.close()
	return render_template('list.html', all=all)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))
	
	
@app.route('/login', methods=['GET', 'POST'])
def login():
	if session.get('logged_in') == True and session['logged_in'] == True:
		return redirect(url_for('list'))
		
	if request.method == 'POST':
		username = request.form['Username']
		password = request.form['Password']

		if len(username) > 0 and len(password) > 0 and username == 'admin' and password == 'password':
			session['logged_in'] = True
			return redirect(url_for('list'))
			
	return render_template('login.html')

	
	
@app.route('/setup', methods=['GET', 'POST'])
def setup():
	computer_name = request.args.get('c', '')
	user_name = request.args.get('u', '')
	password = request.args.get('p', '')
	
	if len(computer_name) > 0 and len(user_name) > 0 and len(password) > 0:
		return insert_computer(computer_name, user_name, password)
	else:
		return "0"
	


@app.route("/")
def index():
	return "Wrong place"

if __name__ == "__main__":
	app.config.from_object(__name__) # load config from this file , flaskr.py
	app.config.update(dict(
		SECRET_KEY='development key',
		USERNAME='admin',
		PASSWORD='default'
	))
	app.config.from_envvar('FLASKR_SETTINGS', silent=True)
	app.run()