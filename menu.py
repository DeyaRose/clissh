#!/usr/bin/env python3
import sys, os, shelve, curses, getpass, traceback, time
import subprocess as sb
from curses import wrapper
# TODO loop through shelf, add known hosts to array, the append "exit" and "add" (opposite of what it is now) (may be removed)
# TODO make the hosts appear in the list they were added
# TODO make a way to sort the hosts differently
# TODO implement different sorting methods - alphabetical, date/time added, etc
# TODO implement "pages" if there are too many hosts (get terminal height and account for that)
# TODO Find if an added host is a duplicate (compare ip, username, port, etc)
#   If they are exact duplicates, tell the user and don't add
#   If no nick is used and the ports are the only difference, display the target as "target (port)"
#      This method should be used for most minor differences if there is no nick.

# constants
NAME = "CliSSH"
BUILD = "1.0b"
VERSION = NAME + " v" + str(BUILD)
PR_DEL = 0.0#4

menuops = []
firstrun = True

# create & loop thru shelf
fdir = os.getenv("HOME") + "/.clissh/" # the path to the hosts file
fname = "hosts"
fullpth = fdir + fname
# if the path doesnt exist,
if not os.path.exists(fdir):
    try:
        # try to make it
        os.system("mkdir -p " + fdir)
    except:
        # if it fails, print an error message.
        print("[!!] Error creating path")

# open the databse 
db = shelve.open(fullpth, flag='c', writeback=True)
max_len = len(menuops)
def refresh_db():
    global menuops
    del menuops[:]
    menuops.append(['Exit'])
    menuops.append(['More'])
    klist = list(db.keys())
    klen = len(klist)
    if klen == 0:   # if the list has nothing (empty),
        # the program should prompt the user to add a host
        pass
    else:   # but if it has stuff,
        global firstrun
        firstrun = False
        for k in db:
            # add it to the menu options.
            menuops.append([k, db[k][0], db[k][1], db[k][2], db[k][3]])
    global max_len
    max_len = len(menuops)

#menuops.append(['<nick>', '<username>', '<password>', '<ip>', '<port>'])

# nick, user, pass, ip, port

# TODO: check and install requirements; openssh & sshpass, getpass #<curses>

def connect(idx):
    if idx < 0:
        raise IndexError('indices cannot be negative')
    user = menuops[idx][1]
    passwd = menuops[idx][2]
    target = menuops[idx][3]
    pt = menuops[idx][4]
    ssh_cmd = ['sshpass', '-p', passwd, 'ssh', user + '@' + target, '-p', pt]
    rcode = sb.run(ssh_cmd)
    return rcode.returncode

def pause(flag=True):
    if flag:
        print("\n(Press <Enter> to continue)")
        input()
    else:
        return

def clear():
    """Clears the screen."""
    sb.run('clear')

def printver():
    print(VERSION)

def printarr(start=0):
    for i in range(0, max_len-start):
        time.sleep(PR_DEL)
        print("{num}. {option}".format(num=i, option=menuops[i+start][0]))

def menu(stdscr):
    """The main menu, where the user picks a host or another option."""
    try:
        refresh_db()
        if firstrun:
            # prompt the user to add a host if none are found
            print("No hosts found. Do you want to add one? (Y/n)")
            ch = input("> ")
            if "yes" in ch or not ch:
                add(None)
                refresh_db()
            else:
                pass
        while True:
            errcode = 0
            clear()
            printver()
            print()
            if errcode == 0:
                print("Main Menu\n")
            else:
                print("[-] Error code:", str(errcode))
                print()
            print("Pick an option:")
            printarr()
            char = input('> ')
            print() # add a space
            flag = True
            try:
                sel = int(char)
                if sel == 0:
                    print('[*] Goodbye!')
                    flag = False
                    return
                elif sel == 1:
                    submenu(None)
                    flag = False
                else:
                    if sel > max_len:
                        raise IndexError('Out of bounds')
                    else:
                        clear()
                        errcode = connect(sel)
                    #print("[i] Error code:", str(errcode))
            except ValueError as v:
                print("[!!] Error: ValueError -- " + str(v))
                del v
            except IndexError as i:
                print("[!!] Error: IndexError -- " + str(i))
                del i
            except Exception as e:
                print("[!!] Error: " + str(e))
                print(traceback.format_exc())
                del e
            finally:
                pause(flag)
            char = ''
    except:
        pass
    finally:
        db.close()

def add(addscr):
    """The function for adding a remote host."""
    prompts = [
        "Enter the username: ",
        "Enter the password: ",
        "Confirm the password: ",
        "Enter the host IP: ",
        "Enter the host port (default 22): ",
        "Enter a nickname for this host (opt.): "
    ]
    # initialize the variables
    user = ''
    passwd = ''
    passwdconf = ''
    target = ''
    port = '22'
    nick = ''
    clear()
    printver()
    print()
    print("Add a Host\n")
    print(prompts[0], end='')
    # ask for the username
    user = input()
    # ask for password & password confirmation
    while passwd is passwdconf: # loop should be entered because both vars are null
        print(prompts[1], end='')
        passwd = getpass.getpass("")
        print(prompts[2], end='')
        passwdconf = getpass.getpass("")
        try:
            if passwdconf != passwd:    # if they didn't match, do it again
                print("[!!] The passwords you entered did not match. (Press <Enter> to retry)", end='')
                # they don't match, so set them back to null so the loop continues
                passwd = ''
                passwdconf = ''
                input()
                # delete the previous lines
                clear()
                printver()
                print()
                print("Add a Host\n")
                print(prompts[0] + user)
            else:
                # the passwords matched, break out of the loop
                passwd = passwd.decode('utf8')
                break
        except:
            pass
    print(prompts[3], end='')
    # get target ip
    target = input()
    print(prompts[4], end='')
    # get target port
    while 1:
        try:
            port = input()
            if not port:
                port = 22
                break
            else:
                if int(port) > 65535 or int(port) < 0:
                    print("[!!] {} is out of range! (0-65535)".format(port))
                else:
                    break
        except ValueError as v:
            print("[!!] Error: ValueError -- " + str(v))
            del v
        except Exception as e:
            print("[!!] Error: " + str(e))
            del e
    # TODO: check that the port is valid (loop)
    print(prompts[5], end='')
    # get the nickname for the target
    nick = input()
    if not nick:
        # if nothing is entered, make it the ip
        nick = str(target)
    # confirm with the user that the entered information was correct
    print("Is the entered information correct? (Y/n)")
    if target == nick:
        print("Target: {}; Port: {}; Username: {}; Password: (hidden)".format(target, port, user))
    else:
        print("Nick: {}; Target: {}; Port: {}; Username: {}; Password: (hidden)".format(nick, target, port, user))
    ch = input("> ")
    if "yes" in ch or not ch:
        # TODO: auto-add fingerprints/etc
        db[nick] = [user, passwd, target, port]
        print("[+] Host added to database located at {}.".format(fullpth))
        db.sync()
        refresh_db()
        pause()
        return
    else:
        add(None)
        pass

def edit(editscr):
    """Edit a host."""
    # TODO
    return

def clearall(cascr):
    """Remove all hosts."""
    cascr.clear()
    cascr.addstr(0, 0, "Clear All", curses.A_REVERSE)
    return

def remove(remscr):
    """Remove a specified host."""
    # del db[<name>]
    while 1:
        clear()
        printver()
        print()
        print("Remove a Host\n")
        print("Select a host to delete (-1 to exit):")
        start = 2   # the index to start printing at
        printarr(start)
        ch = input("> ")
        try:
            sel = int(ch)
            if sel == -1:
                return
            if sel < 0 or sel > max_len-start:
                raise ValueError('Invalid selection')
            else:
                deletion = menuops[sel+start]
                if deletion[0] == deletion[3]:
                    print("Delete {ip}? This cannot be undone. (Y/n)".format(ip=deletion[0]))
                else:
                    print("Delete {nick} ({ip})? This cannot be undone. (Y/n)".format(nick=deletion[0], ip=deletion[3]))
                choice = input("> ")
                if choice in "yes" or not choice:
                    del db[deletion[0]]
                    db.sync()
                    refresh_db()
                    print("Deletion successful.")
                    break
                else:
                    print("Not deleted.")
                pause()
        except ValueError as v:
            print("[!!] Error: ValueError -- " + str(v))
            del v
    pause()
    return

def submenu(subscr):
    """The submenu function where the user can select any other function."""
    subops = []
    subops.append('Back')
    subops.append('Add')
    subops.append('Edit')
    subops.append('Remove')
    subops.append('Clear all')
    subops_len = len(subops)
    #subscr.clear()
    #subscr.addstr(0, 0, "More Options", curses.A_REVERSE)
        #subscr.move(1, 0)
    char = ''
    while True:
        clear()
        printver()
        print()
        print("More Options\n")
        print("Pick an option:")
        for j in range(0, subops_len):
            time.sleep(PR_DEL)
            print("{num}. {option}".format(num=j, option=subops[j]))
        ch = input("> ")
        try:
            sel = int(ch)
            if sel == subops.index('Back'):
                return
            elif sel == subops.index('Add'):
                add(None)
                break
            elif sel == subops.index('Edit'):
                edit(None)
                break
            elif sel == subops.index('Remove'):
                remove(None)
                break
            elif sel == subops.index('Clear all'):
                clearall(None)
                break
            else:
                print("\n[!!] Invalid answer")
                pause()
        except ValueError as v:
            print("[!!] Error: ValueError -- " + str(v))
            del v
        except Exception as e:
            print("[!!] Error: " + str(e))
            del e

# start the program at the menu() function
if __name__ == "__main__":
    menu(None)
