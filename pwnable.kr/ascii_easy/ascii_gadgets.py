from pwn import *

### defines ###
BASE_ADDR = 0x5555e000 # Binary base address

### globals ###
gadgets_list = []
ascii_gadgets_list = []

def is_ascii(ch):
    """
    Accept only chars between 0x20 to 0x7f.
    """
    return ch >= 0x20 and ch <= 0x7f

def is_addr_ascii(addr):
    """
    Check if all the bytes in given address are ascii bytes.
    """
    for ch in p32(addr):
        if not is_ascii(ch):
            return False
    return True

def main():
    log.info("Start read gadgets from gadgets.txt file...")
    with open("gadgets.txt", 'r') as gadgets_file:
        gadgets_list = gadgets_file.read().split('\n')
    log.info("Finish read gadgets.txt!")

    log.info("Search for ascii gadgets...")
    for line in gadgets_list:
        if line.startswith('0x'):
            address = eval(line.split(" : ")[0])
            if is_addr_ascii(BASE_ADDR + address):
                new_line = line.split(" : ")[1]
                ascii_gadgets_list.append(hex(BASE_ADDR + address) + " : "  + new_line)
    log.info("Finish search!")

    with open("ascii_gadgets.txt", "w") as ascii_gadgets_file:
        ascii_gadgets_file.write('\n'.join(ascii_gadgets_list))
    log.info("Write ascii gadgets into ascii_gadgets.txt file.")

if __name__ == "__main__":
    main()
