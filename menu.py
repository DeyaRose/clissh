#!/usr/bin/env python
import sys, os, shelve, curses
from curses import wrapper
# TODO loop through shelf, add known hosts to array, the append "exit" and "add"
menuops = []
menuops.append(['exit'])
menuops.append(['more'])	# TODO

firstrun = True

# create & loop thru shelf
fdir = os.getenv("HOME") + "/.clissh/"
fname = "hosts"
fullpth = fdir + fname
if not os.path.exists(fdir):
	try:
		os.system("mkdir -p " + fdir)
	except:
		print("[!!] Error creating path")


db = shelve.open(fullpth, flag='c', writeback=True)
klist = list(db.keys())
klen = len(klist)
if klen == 0:
	# this means the program should prompt the user to add a host
	pass
else:
	firstrun = False
	for k in db:
		menuops.append(k, db[k][0], db[k][1], db[k][2], db[k][3])

#menuops.append(['<nick>', '<username>', '<password>', '<ip>', '<port>'])
max_len = len(menuops) 

# nick, user, pass, ip, port

# TODO: check and install requirements; openssh & sshpass, curses

def menu(stdscr):
	try:
		stdscr.clear()
		if firstrun:
			reruncmd = ""
			stdscr.addstr(0, 0, "No hosts found. Do you want to add one? (Y/n)", curses.A_REVERSE)
			ch = stdscr.getch()
			if ch == 121 or ch == 10:
				stdscr.clear()
				wrapper(add)
			elif ch == 110:
				pass
		stdscr.clear()
		curses.noecho()
		maxy, maxx = stdscr.getmaxyx()
		curses.curs_set(1)
		stdscr.addstr(0, 0, "Pick an option:", curses.A_REVERSE)
		for i in range(1, max_len+1):
			stdscr.addstr(i, 0, "%d. %s" % (i, menuops[i-1][0]))
		stdscr.move(1, 0)
		char = ''
		while True:
			stdscr.refresh()
			cury, _ = stdscr.getyx()
			char = stdscr.getch()
			# TODO if numeric, go to that line number (the choice)
			# k or 107
			if char == 107:	# move up
				if cury == 1:
					stdscr.move(max_len, 0)
				else:
					stdscr.move(cury-1, 0)
			# j or 106
			if char == 106:	# move down
				if cury == max_len:
					stdscr.move(1, 0)
				else:
					stdscr.move(cury+1, 0)
			if char == 10:		# line feed
				curses.flash()
				if cury == 1:	# exit
					return
				elif cury == 2:	# more
					stdscr.clear()
					wrapper(submenu)
					# pass	# TODO
					#submenu(curses.initscr())
					#stdscr.redrawwin()
					#stdscr.refresh()
				else:
					sel = cury - 1
					curses.endwin()
					user = menuops[sel][1]
					passwd = menuops[sel][2]
					target = menuops[sel][3]
					pt = menuops[sel][4]
					ssh_cmd = " sshpass -p " + passwd + " ssh " + user + "@" + target + " -p " + pt
					os.system(ssh_cmd)
					pass
			char = ''
	except:
		pass
	finally:
		db.close()

def add(addscr):
	prompts = [
		"Enter the username: ",
		"Enter the password: ",
		"Confirm the password: ",
		"Enter the host IP: ",
		"Enter the host port (default 22): ",
		"Enter a nickname for this host: "
	]
	user = ''
	passwd = ''
	passwdconf = ''
	target = ''
	port = '22'
	nick = '(untitled)'
	ok = False
	curses.curs_set(0)
	curses.echo()
	addscr.addstr(0, 0, "Add a Host", curses.A_REVERSE)
	addscr.addstr(1, 0, prompts[0])
	addscr.refresh()
	user = addscr.getstr(1, len(prompts[0]), 32).decode('utf8')
	
	curses.noecho() # for passwords
	while passwd is passwdconf:
		addscr.addstr(2, 0, prompts[1])
		addscr.refresh()
		passwd = addscr.getstr(2, len(prompts[1]))
				
		addscr.addstr(3, 0, prompts[2])
		addscr.refresh()
		passwdconf = addscr.getstr(3, len(prompts[2]))
		try:
			if passwdconf != passwd:
				addscr.addstr(4, 0, "[!!] The passwords you entered did not match. (Press any key to retry)", curses.A_REVERSE)
				passwd = ''
				passwdconf = ''
				addscr.getkey()
				addscr.deleteln()
				addscr.move(3, 0)
				addscr.deleteln()
				addscr.move(2, 0)
				addscr.deleteln()
			else:
				passwd = passwd.decode('utf8')
				break
		except:
			pass
	
	curses.echo()
	addscr.addstr(4, 0, prompts[3])
	addscr.refresh()
	target = addscr.getstr(4, len(prompts[3]), 255).decode('utf8')

	addscr.addstr(5, 0, prompts[4])
	addscr.refresh()
	port = addscr.getstr(5, len(prompts[4]), 5).decode('utf8')
	if not port:
		port = '22'
	if int(port) > 65535 or int(port) < 0:
		addscr.addstr(6, 0, "[!!] %d is out of range! (0-65535)" % int(port))
		port = '22'
	# TODO: check that the port is valid (loop)

	addscr.addstr(6, 0, prompts[5])
	addscr.refresh()
	nick = addscr.getstr(6, len(prompts[5]), 32).decode('utf8')
	if not nick:
		nick = '(untitled)'

	curses.noecho()
	addscr.addstr(9, 0, "Is the entered information correct? (Y/n)")
	addscr.addstr(10, 0, "Nick: %s; Target: %s; Port: %s; Username: %s; Password: (hidden)" % (nick, target, port, user))
	ch = addscr.getch()
	if ch == 121 or ch == 10:
		# TODO: add to the shelf
		# TODO: make untitled keys increment in number to avoid overwriting
		db[nick] = [user, passwd, host, port]
		addscr.addstr(12, 0, "[+] Host added to database. Press any key to continue.", curses.A_REVERSE)
		addscr.getkey()
		db.sync()
		pass
	else:
		addscr.clear()
		addscr.endwin()
		wrapper(add) # TODO: clear & redo
	return

def edit(editscr):
	pass

def clearall(cascr):
	pass

def remove(remscr):
	pass

def submenu(subscr):
	subops = []
	subops.append('Back')
	subops.append('Add')
	subops.append('Edit')
	subops.append('Remove')
	subops.append('Clear all')
	subops_len = len(subops)
	subscr.clear()
	subscr.addstr(0, 0, "More Options", curses.A_REVERSE)
	for j in range(1, subops_len+1):
		subscr.addstr(j, 0, "%d. %s" % (j, subops[j-1]))
	subscr.move(1, 0)
	char = ''
	while True:
		cury, _ = subscr.getyx()
		char = subscr.getch()
		if char == 107:
			if cury == 1:
				subscr.move(subops_len, 0)
			else:
				subscr.move(cury-1, 0)
		if char == 106:
			if cury == subops_len:
				subscr.move(1, 0)
			else:
				subscr.move(cury+1, 0)
		if char == 10:
			curses.flash()
			if cury == 1:
				# TODO fix
				subscr.clear()
				subscr.endwin()
				return
			elif cury == 2:
				subscr.endwin()
				wrapper(add)
			elif cury == 3:
				# TODO: edit
				wrapper(edit)
			elif cury == 4:
				# TODO remove
				wrapper(remove)
			elif cury == 5:
				wrapper(clearall)
				# TODO clear all (with an extra check or two to make sure)
			else:
				pass

if __name__ == "__main__":
	wrapper(menu)
