#!/usr/bin/env python3
import sys, os, shelve, curses, getpass, traceback, time
import subprocess as sb
# TODO implement different sorting methods - alphabetical, date/time added, etc
# TODO implement "pages" if there are too many hosts (get terminal height and account for that)
# TODO Find if an added host is a duplicate (compare ip, username, port, etc)
#   If they are exact duplicates, tell the user and don't add
#   If no nick is used and the ports are the only difference, display the target as "target (port)"
#      This method should be used for most minor differences if there is no nick.
# TODO encrypt the data with a password
# TODO make the user enter a password on start to decrypt the data
# TODO multiple-user support (?)
# TODO add the ability to run custom commands on connect

# constants
NAME = "CliSSH"
BUILD = "1.0b"
VERSION = NAME + " v" + str(BUILD)

menuops = []
firstrun = True

prompts = [
    "Enter the username: ",
    "Enter the password: ",
    "Confirm the password: ",
    "Enter the host IP: ",
    "Enter the host port (default 22): ",
    "Enter a nickname for this host{}: "
]

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

max_len = 0
def refresh_db():
    global menuops
    del menuops[:]
    global firstrun
    menuops.append(['Exit'])
    menuops.append(['More'])
    klist = list(db.keys())
    klen = len(klist)
    if klen == 0:   # if the database is empty,
        # the program should prompt the user to add a host
        firstrun = True
    else:   # but if it has stuff,
        firstrun = False
        counter = 0
        for _ in range(klen):
            for k in db:
                # add it to the menu options.
                if db[k][4] == counter:
                    menuops.append([k, db[k][0], db[k][1], db[k][2], db[k][3], db[k][4]])
            counter += 1
    global max_len
    max_len = len(menuops)

#menuops.append(['<nick>', '<username>', '<password>', '<ip>', '<port>', '<number>'])

# nick, user, pass, ip, port, number

# TODO: check and install requirements; openssh & sshpass, getpass

def connect(idx):
    if idx < 0:
        raise IndexError('indices cannot be negative')
    user = menuops[idx][1]
    passwd = menuops[idx][2]
    target = menuops[idx][3]
    pt = menuops[idx][4]
    ssh_cmd = ['sshpass', '-p', passwd, 'ssh', user + '@' + target, '-p', str(pt)]
    rcode = sb.run(ssh_cmd)
    return rcode.returncode

def listdata():
    klist = list(db.keys())
    klen = len(klist)
    for x in klist:
        print("Key: {}".format(db[x]))
    pause()

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
    print()

def printarr(start=0, list_one=False):
    for i in range(0 if not list_one else 1, max_len-start + (0 if not list_one else 1)):
        print("{num}. {option}".format(num=i, option=menuops[i+start - (0 if not list_one else 1)][0]))

def check_duplicates(in_arr):
    klist = list(db.keys())
    klen = len(klist)
    if not len(in_arr) == 6:
        print("Not the same length")
        return False
    counter = 0
    for k in klist:
        for x in range(6):
            if not in_arr[x] == db[k][x]:
                print("Mismatch on idx {}: {} | {}".format(x, in_arr[x], db[k][x]))
                return False
    print("No mismatches")
    return True


def menu():
    """The main menu, where the user picks a host or another option."""
    try:
        refresh_db()
        if firstrun:
            # prompt the user to add a host if none are found
            clear()
            printver()
            print("No hosts found. Do you want to add one? (Y/n)")
            ch = input("> ")
            if ch in "yes" or not ch:
                add()
                refresh_db()
            else:
                pass
        while True:
            errcode = 0
            clear()
            printver()
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
                    submenu()
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
            except EOFError:
                flag = False
                return
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

def add_user():
    # Ask for the username
    return input(prompts[0])

def add_pass():
    # Get the password
    passwd = ''
    passwdconf = ''
    # ask for password & password confirmation
    while passwd is passwdconf: # loop should be entered because both vars are null
        print(prompts[1], end='')
        passwd = getpass.getpass("")
        print(prompts[2], end='')
        passwdconf = getpass.getpass("")
        try:
            if passwdconf != passwd:    # if they didn't match, do it again
                return None
            else:
                # the passwords matched, break out of the loop
                passwd = passwd.decode('utf8')
                break
        except:
            pass
    return passwd

def add_target():
    # Ask for the target IP
    return input(prompts[3])

def add_port():
    # Ask for the port
    while 1:
        try:
            port = input(prompts[4])
            if not port:
                port = '22'
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
    return port

def add_nick(flag=True):
    nick = input(prompts[5].format(" (opt.)" if flag else ""))
    return None if not nick else nick

def add():
    """The function for adding a remote host."""
    # initialize the variables
    n = len(list(db.keys()))
    user = ''
    passwd = ''
    target = ''
    port = '22'
    nick = ''
    clear()
    printver()
    print("Add a Host\n")
    #print("Number: " + str(n))
    # ask for the username
    user = add_user()
    while 1:
        # delete the previous lines
        passwd = add_pass()
        if passwd is not None:
            break
        print("[!!] The passwords you entered did not match. (Press <Enter> to retry)", end='')
        # they don't match, so set them back to null so the loop continues
        passwd = ''
        passwdconf = ''
        input()
        # Delete the previous lines
        clear()
        printver()
        print("Add a Host\n")
        print(prompts[0] + user)
    target = add_target()
    port = add_port()
    nick = add_nick()
    if nick is None:
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
        # loop through and find number
        addition = [user, passwd, target, port, n]
        db[nick] = addition
        print("[+] Host added to database located at {}.".format(fullpth))
        db.sync()
        refresh_db()
        pause()
        return
    else:
        add(None)
        pass

def edit():
    """Edit a host."""
    # TODO
    start = 2
    flag = True
    while 1:
        clear()
        printver()
        print("Edit a Host\n")
        print("Select a host to edit:")
        print("0. Back")
        printarr(start, True)
        ch = input("> ")
        print()
        try:
            sel = int(ch)
            if sel == 0:
                flag = False
                return
            if sel < 0 or sel > max_len-start+1:
                raise ValueError('Invalid selection')
            else:
                edit_opts = []
                edit_opts.append('Back')
                edit_opts.append('Nick')
                edit_opts.append('Username')
                edit_opts.append('Password')
                edit_opts.append('Target')
                edit_opts.append('Port')
                while 1:
                    selection = menuops[sel+start-1]
                    clear()
                    printver()
                    print("Editing {}".format(selection[0] if not selection[0] == selection[3] else selection[3]) + "\n")
                    print("Select an option:")
                    for opt in range(len(edit_opts)):
                        print("{}. {}".format(opt, edit_opts[opt]))
                    choice = input("> ")
                    print()
                    sln = int(choice)
                    dupe = False
                    # TODO for all: if data is same as before, make no change
                    if sln == edit_opts.index('Back'):
                        flag = False
                        break # Go back to selecting a host
                    elif sln == edit_opts.index('Nick'):
                        old_nick = selection[0]
                        print("Old nick:", old_nick if not selection[0] == selection[3] else "<none>")
                        new_nick = add_nick(False)
                        if new_nick:
                            # checking for duplicate keys
                            for n in list(db.keys()):
                                if not new_nick == n:
                                    pass
                                    #print("No Duplicates")
                                else:
                                    #print("Duplicates exist")
                                    dupe = True
                                    break
                            if dupe:
                                print("[!!] Error: Duplicate nick")
                            else:
                                # There are no duplicates
                                # TODO: Check if it's ok to change
                                db[new_nick] = db[old_nick]
                                del db[old_nick]
                                print("Nickname updated to {}".format(new_nick))
                        else:
                            pass
                    elif sln == edit_opts.index('Username'):
                        # TODO username verification?? e.g. spaces/symbols?
                        old_user = selection[1]
                        print("Old username:", old_user)
                        new_user = add_user()
                        if new_user:
                            print("New username:", new_user)
                            #edited = [selection[0], new_user, selection[2], selection[3], selection[4], selection[5]]
                            if new_user == old_user:
                                print("Duplicate usernames; no change")
                            else:
                                db[selection[0]][0] = new_user
                                print("\nUsername updated.")
                        else:
                            print("[i] No username given.")
                            # ask whether or not they meant to and if yes, exit, otherwise do it again
                    elif sln == edit_opts.index('Password'):
                        old_pass = selection[2]
                        print("Edit password:")
                        while 1:
                            new_pass = add_pass()
                            if new_pass is not None:
                                break
                            elif not new_pass:
                                print("[i] No password given.")
                                break
                            else:
                                if old_pass == new_pass:
                                    print("Duplicate passwords; no change")
                                else:
                                    db[selection[0]][1] = new_pass
                                    print("\nPassword updated.")
                    elif sln == edit_opts.index('Target'):
                        old_target = selection[3]
                        print("Old target:", str(old_target))
                        new_target = add_target()
                        if new_target:
                            print("New target:", new_target)
                            if new_target == old_target:
                                print("Duplicate targets; no change")
                            else:
                                db[selection[0]][2] = new_target
                                print("\nTarget updated.")
                    elif sln == edit_opts.index('Port'):
                        old_port = selection[4]
                        print("Old port:", str(old_port))
                        new_port = add_port()
                        if new_port == old_port:
                            print("Duplicate ports; no change")
                        else:
                            db[selection[0]][3] = new_port
                            print("New port:", str(new_port))
                    else:
                        print('[!!] Invalid selection.') # Try again
                    refresh_db()
                    pause(flag)
        except ValueError as v:
            print("[!!] Error: ValueError -- " + str(v))
            del v
        except EOFError:
            flag = False
            return
        except Exception as e:
            print("[!!] Error: " + str(e))
            print(traceback.format_exc())
        finally:
            pause(false)

def clearall():
    """Remove all hosts."""
    clear()
    printver()
    print("Clear All Hosts\n")
    print("Clearing all hosts will remove all stored data about the hosts.")
    print("You will not be able to recover the information.\n")
    print("Continue? (y/N)")
    ch = input("> ")
    print()
    if ch in "yes":
        # TODO: ask again for confirmation
        for k in db.keys():
            del db[k]
        if len(db.keys()) == 0:
            print("[i] All keys cleared.")
        else:
            print("More than 0 keys")
        refresh_db()
    else:
        print("Not deleting.")
    pause()

def remove():
    """Remove a specified host."""
    # del db[<name>]
    while 1:
        clear()
        printver()
        print("Remove a Host\n")
        print("Select a host to delete:")
        start = 2   # the index to start printing at
        print("0. Back")
        printarr(start, True)
        ch = input("> ")
        try:
            sel = int(ch)
            if sel == 0:
                return
            if sel < 0 or sel > max_len-start+1:
                raise ValueError('Invalid selection')
            else:
                deletion = menuops[sel+start-1]
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
        except EOFError:
            return
    pause()
    return

def view():
    start = 2
    flag = True
    while 1:
        clear()
        printver()
        print("View a Host\n")
        print("Select a host to view the data for):")
        print("0. Back")
        printarr(start, True)
        ch = input("> ")
        print()
        try:
            sel = int(ch)
            if sel == 0:
                flag = False
                return
            if sel < 0 or sel > max_len-start:
                raise ValueError('Invalid selection')
            else:
                lookup = menuops[sel+start-1]
                if not lookup[0] == lookup[3]:
                    print("Nick: {}".format(lookup[0]))
                print("User: {}".format(lookup[1]))
                print("Pass: (hidden)")
                print("Target: {}".format(lookup[3]))
                print("Port: {}".format(lookup[4]))
                #print("Number: {}".format(lookup[5]))
        except ValueError as v:
            print("[!!] Error: ValueError -- " + str(v))
            del v
        except IndexError as i:
            print("[!!] Error: IndexError -- " + str(i))
            del i
        except EOFError:
            return
        except Exception as e:
            print("[!!] Error: " + str(e))
            print(traceback.format_exc())
            del e
        finally:
            pause(flag)

def submenu():
    """The submenu function where the user can select any other function."""
    subops = []
    subops.append('Back')
    subops.append('Add')
    subops.append('View')
    subops.append('Edit')
    subops.append('Remove')
    subops.append('Clear all')
    subops.append('Print All Data')
    subops_len = len(subops)
    while True:
        clear()
        printver()
        print("More Options\n")
        print("Pick an option:")
        for j in range(0, subops_len):
            print("{num}. {option}".format(num=j, option=subops[j]))
        ch = input("> ")
        try:
            sel = int(ch)
            if sel == subops.index('Back'):
                return
            elif sel == subops.index('Add'):
                add()
                break
            elif sel == subops.index('Edit'):
                edit()
                break
            elif sel == subops.index('Remove'):
                remove()
                break
            elif sel == subops.index('Clear all'):
                clearall()
                break
            elif sel == subops.index('View'):
                view()
            elif sel == subops.index('Print All Data'):
                listdata()
            else:
                print("\n[!!] Invalid answer")
                pause()
        except ValueError as v:
            print("[!!] Error: ValueError -- " + str(v))
            del v
        except EOFError:
            return
        except Exception as e:
            print("[!!] Error: " + str(e))
            del e

# start the program at the menu() function
if __name__ == "__main__":
    menu()
