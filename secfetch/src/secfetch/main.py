from secfetch.secfetch import get_kernel, get_aslr


def main():
    print("secfetch v0.1")
    print("Kernel:", get_kernel())
    print("ASLR:", get_aslr())
