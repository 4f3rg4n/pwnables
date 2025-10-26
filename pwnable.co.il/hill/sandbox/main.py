import json
import subprocess


def validate_json(command_json):
    d = json.loads(command_json)
    assert 'users' in d
    assert 'cmds' in d
    assert 'args' in d
    assert not 'admin' in d['users']
    assert all(type(i)==str for i in d['users'])
    assert all(type(i)==str for i in d['cmds'])
    assert all(type(i)==list for i in d['args'])
    for arg in d['args']:
        assert all(type(i)==str for i in arg)
    return True


def send_command_to_sandbox(command_json):
    proc = subprocess.Popen(['./sandbox_service'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE);
    out, err = proc.communicate(command_json.encode())
    if err:
        print('Error in execution')
        return
    print(f'Output: {out.decode()}')


def main():
    command_json = input('Enter command to run: ')
    if validate_json(command_json):
        send_command_to_sandbox(command_json)
    


if __name__ == '__main__':
    main()