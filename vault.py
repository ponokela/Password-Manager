import os.path
from os import path
import atexit
import tkinter as tk
from tkinter import ttk
try:
    from Crypto.Cipher import AES
except:
    print("Module PyCryptoDome is required but not installed")
    print("install by typing 'pip3 install pycryptodome' in terminal")
from listfuncs import listtostring, stringtolist


class Vault:
    # private
    def __init__(self, vault_name, password):
        self.vault_name = "Vaults/" + vault_name + "_vault"
        self.vault_text = []

        if (path.isfile(self.vault_name)):
            return

        vault = open(self.vault_name, "wb")
        vault.close()
        self.vault_text.append(password + b'\n')

    def __checkPassword(self, text, password):
        try:
            vaultPass = text[0:text.index(b'\n')]
            return (vaultPass == password)
        except:
            return False

    # public
    def addLogin(self, website, username, password):
        inserted = False
        new_login = f'{website} {username} {password}'.encode('utf-8')
        bytesite = website.encode('utf-8')
        for i in range(1, len(self.vault_text)):
            if bytesite < self.vault_text[i]:
                inserted = True
                self.vault_text.insert(i, new_login)
                break
        if not inserted:
            self.vault_text.append(new_login)

    def encrypt(self):
        text = listtostring(self.vault_text, b'\n')
        key = text[0:text.index(b'\n')]
        vault = text

        cipher = AES.new(key, AES.MODE_EAX)
        ciphervault = cipher.encrypt(vault).hex()

        vault = open(self.vault_name, "wt")
        vault.write(cipher.nonce.hex() + "\n")
        vault.write(ciphervault)

    def decrypt(self, key):
        text = open(self.vault_name, "rt").read()
        split = text.index("\n")
        nonce = bytes.fromhex(text[0:split])
        vault = bytes.fromhex(text[split+1:len(text)])

        cipher = AES.new(key, AES.MODE_EAX, nonce)
        plainvault = cipher.decrypt(vault)
        success = self.__checkPassword(plainvault, key)

        if success:
            self.vault_text = stringtolist(plainvault, b'\n')
        return success

    def display(self, menuwin):
        # Hide menu window that accessed this vault
        menuwin.withdraw()

        # Main Window
        vaultwin = tk.Tk()
        vaultwin.title(self.vault_name[7:-6])

        # Vault Frame
        frm_vault = ttk.Frame(master=vaultwin, padding=10)
        frm_vault.grid(column=0, row=0,
                       sticky=tk.NSEW)
        vaultwin.columnconfigure(0, weight=1)
        vaultwin.rowconfigure(0, weight=1)

        # Display vault contents
        tree_vault = ttk.Treeview(master=frm_vault,
                                  columns=("website", "username", "password"))
        tree_vault.heading('website', text='Website')
        tree_vault.heading('username', text='Username')
        tree_vault.heading('password', text='Password')
        tree_vault['show'] = 'headings'

        # Populate tree with vault contents
        def populate_tree():
            first = True
            for entry in self.vault_text:
                if first:
                    first = False
                    continue
                tree_vault.insert("", tk.END, text="", values=entry)
        populate_tree()

        tree_vault.grid(column=0, row=0, columnspan=2,
                        sticky=tk.NSEW)
        scrlbr_vault = ttk.Scrollbar(master=frm_vault, orient=tk.VERTICAL,
                                     command=tree_vault.yview)
        tree_vault['yscrollcommand'] = scrlbr_vault.set
        scrlbr_vault.grid(column=2, row=0,
                          sticky=tk.NS)

        # Vault Buttons
        btn_addlogin = ttk.Button(master=frm_vault,
                                  text="Add Information")
        btn_addlogin.grid(column=0, row=1,
                          sticky=tk.EW)
        btn_logout = ttk.Button(master=frm_vault,
                                text="Logout User")
        btn_logout.grid(column=1, row=1,
                        sticky=tk.EW)

        for child in frm_vault.winfo_children():
            child.grid_configure(padx=5, pady=5)

        frm_vault.columnconfigure(0, weight=1)
        frm_vault.columnconfigure(1, weight=1)
        frm_vault.rowconfigure(0, weight=1)
        frm_vault.rowconfigure(1, weight=1)

        # Add Login Frame
        frm_addlogin = ttk.Frame(master=vaultwin, padding=10)
        frm_addlogin.grid(column=0, row=1,
                          sticky=tk.NSEW)
        frm_addlogin.grid_remove()

        lbl_website = ttk.Label(master=frm_addlogin,
                                text="Website:")
        lbl_website.grid(column=0, row=0)
        lbl_username = ttk.Label(master=frm_addlogin,
                                 text="Username:")
        lbl_username.grid(column=0, row=1)
        lbl_password = ttk.Label(master=frm_addlogin,
                                 text="Password:")
        lbl_password.grid(column=0, row=2)

        ent_website = ttk.Entry(master=frm_addlogin)
        ent_website.grid(column=1, row=0,
                         sticky=tk.EW)
        ent_username = ttk.Entry(master=frm_addlogin)
        ent_username.grid(column=1, row=1,
                          sticky=tk.EW)
        ent_password = ttk.Entry(master=frm_addlogin)
        ent_password.grid(column=1, row=2,
                          sticky=tk.EW)

        sep_ents_btns = ttk.Separator(master=frm_addlogin,
                                      orient=tk.VERTICAL)
        sep_ents_btns.grid(column=2, row=0, rowspan=3,
                           sticky=tk.NS)

        btn_submit = ttk.Button(master=frm_addlogin,
                                text="Add")
        btn_submit.grid(column=3, row=0,
                        sticky=tk.EW)
        btn_cancel = ttk.Button(master=frm_addlogin,
                                text="Cancel")
        btn_cancel.grid(column=3, row=1,
                        sticky=tk.EW)

        for child in frm_addlogin.winfo_children():
            child.grid_configure(padx=5, pady=5)

        frm_addlogin.columnconfigure(0, weight=1)
        frm_addlogin.columnconfigure(1, weight=1)
        frm_addlogin.columnconfigure(2, weight=1)
        frm_addlogin.columnconfigure(3, weight=1)
        frm_addlogin.rowconfigure(0, weight=1)
        frm_addlogin.rowconfigure(1, weight=1)
        frm_addlogin.rowconfigure(2, weight=1)

        # reset addlogin Frame
        def reset_frm_addlogin():
            ent_website.delete(0, tk.END)
            ent_password.delete(0, tk.END)
            ent_username.delete(0, tk.END)
            ent_website.focus()

        # handle showing menu to add login info
        def handle_addlogin():
            ent_website.focus()
            frm_addlogin.grid()
        btn_addlogin.configure(command=handle_addlogin)

        # handle exiting adding login option
        def handle_cancel():
            reset_frm_addlogin()
            frm_addlogin.grid_remove()
        btn_cancel.configure(command=handle_cancel)

        # handle sumbiting adding login info
        def handle_submit():
            website = ent_website.get()
            username = ent_username.get()
            password = ent_password.get()

            reset_frm_addlogin()

            if (website == "" or username == "" or password == ""):
                return

            self.addLogin(website, username, password)

            tree_vault.delete(*tree_vault.get_children())
            populate_tree()
        btn_submit.configure(command=handle_submit)

        # handle using enter to submit login info
        def handle_enter(event):
            handle_submit()
        vaultwin.bind('<Return>', handle_enter)

        # handle logging out/quitting application
        def handle_logout():
            self.encrypt()
            vaultwin.destroy()
            menuwin.deiconify()
        btn_logout.configure(command=handle_logout)
        vaultwin.protocol('WM_DELETE_WINDOW', handle_logout)

        # handle force quit
        def handle_forcequit():
            self.encrypt()
        atexit.register(handle_forcequit)

        vaultwin.mainloop()
