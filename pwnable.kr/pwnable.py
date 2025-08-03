from pwn import *
import json

sessions = []
g_user = 'fd'

def command(shell: process, cmd: str, var:str = '') -> str:
    shell.sendline(cmd)
    if len(var):
        shell.sendline(var)
    return shell.recvuntil('\n').decode()#[:-3]

def update_sessions(shell: process):
    global sessions
    sessions = eval(command(shell, 'TERM=dumb loginctl --no-pager --output=json').replace(' ', ''))

def print_sessions():
    global sessions
    for session in sessions:
        print(f"Session ID: {session['session']}")
        print(f"User: {session['user']}")
        print(f"UID: {session['uid']}")
        print(f"TTY: {session['tty']}")
        print(f"Seat: {session['seat']}")
        print("="*30)

def get_session_info(shell: process, session_id: str):
    global sessions
    return command(shell, f'TERM=dumb loginctl show-session {session_id}')

def get_session_user(shell: process, session_id: str):
    global sessions
    for session in sessions:
        if session['session'] == session_id:
            return session['user']
    return None

def switch_user(shell: process, user: str):
    global sessions
    command(shell, f'su {user}', "guest")
    command(shell, 'cd ~')
    #print(shell.recvline())


def menu():
    print("1. List sessions")
    print("2. Get session info")
    print("3. Kill session")
    print("0. Exit")

def main():
    global g_user
    ssh_conn = ssh(user='fd', host='pwnable.kr', password='guest', port=2222)

    # Run a command on the remote host
    shell = ssh_conn.process('/bin/sh')
    print(shell.recvuntil('$').decode())
    switch_user(shell, "otp")
    while True:
        menu()
        choice = input("Enter your choice: ")
        if choice == '1':
            update_sessions(shell)
            print_sessions()
        elif choice == '2':
            session_id = input("Enter session ID: ")
            print(get_session_info(shell, session_id))
        elif choice == '3':
            session_id = input("Enter session ID to kill: ")
            user = get_session_user(shell, session_id)
            if user is None:
                print("Session not found.")
                continue
            if g_user != user:
                switch_user(shell, user)
                g_user = user
            print(command(shell, f'loginctl terminate-session {session_id}'))
            print(f"Session {session_id} killed.")
        elif choice == '0':
            break
        else:
            print("Invalid choice. Please try again.")

    ssh_conn.close()

if __name__ == "__main__":
    main()
