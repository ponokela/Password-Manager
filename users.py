import os.path
from os import path
from functools import partial
import tkinter as tk
from tkinter import ttk
try:
    from Crypto.Hash import MD5
except:
    print("Module PyCryptoDome is required but not installed")
    print("Install with 'pip3 install pycryptodome' in terminal")
from vault import Vault


class Users:
    # private
    def __init__(self):
        self.allAccounts = {}

        for file in os.listdir("Vaults/"):
            filename = os.fsdecode(file)
            if filename.endswith('_vault'):
                username = filename[0:-6]
                self.allAccounts.update({username: Vault(username, None)})

    def __hash(self, string):
        md5 = MD5.new()
        md5.update(string.encode('utf-8'))
        return md5.hexdigest().encode('utf-8')

    # public
    def createAccount(self, username, password):
        if (self.allAccounts.get(username, False)):
            return 1

        password = self.__hash(password)

        self.allAccounts.update({username: Vault(username, password)})
        vault = self.allAccounts.get(username)
        return vault

    def accessAccount(self, username, password):
        vault = self.allAccounts.get(username, 1)
        if (vault == 1):
            return 1

        password = self.__hash(password)
        decrypted = vault.decrypt(password)
        if decrypted:
            return vault
        else:
            return 2

    def display(self):
        # Main Window
        accwin = tk.Tk()
        accwin.title("Password Manager")

        # Menu Frame
        frm_menu = ttk.Frame(master=accwin, padding=10)
        frm_menu.grid(column=0, row=0,
                      sticky=tk.NSEW)
        accwin.columnconfigure(0, weight=1)
        accwin.rowconfigure(0, weight=1)

        lbl_greeting = ttk.Label(master=frm_menu, justify=tk.CENTER,
                                 text="Welcome to Password Manager!\n" +
                                      "Please login or sign up below.")
        lbl_greeting.grid(column=0, row=0, columnspan=2,
                          sticky=tk.NS)

        btn_login = ttk.Button(master=frm_menu,
                               text="Login to an existing account")
        btn_login.grid(column=0, row=1, columnspan=1,
                       sticky=tk.EW)
        btn_signup = ttk.Button(master=frm_menu,
                                text="Sign up for a new account")
        btn_signup.grid(column=1, row=1, columnspan=1,
                        sticky=tk.EW)

        for child in frm_menu.winfo_children():
            child.grid_configure(padx=5, pady=5)

        frm_menu.columnconfigure(0, weight=1)
        frm_menu.columnconfigure(1, weight=1)
        frm_menu.rowconfigure(0, weight=1)
        frm_menu.rowconfigure(1, weight=1)

        # Login Frame
        frm_login = ttk.Frame(master=accwin, padding=10)
        frm_login.grid(column=0, row=0,
                       sticky=tk.NSEW)
        frm_login.grid_remove()

        lbl_username = ttk.Label(master=frm_login,
                                 text="Username:")
        lbl_username.grid(column=0, row=0)
        lbl_password = ttk.Label(master=frm_login,
                                 text="Password:")
        lbl_password.grid(column=0, row=1)

        ent_username = ttk.Entry(master=frm_login)
        ent_username.grid(column=1, row=0,
                          sticky=tk.EW)
        ent_password = ttk.Entry(master=frm_login,
                                 show='*')
        ent_password.grid(column=1, row=1,
                          stick=tk.EW)

        btn_back = ttk.Button(master=frm_login,
                              text="Back")
        btn_back.grid(column=0, row=2,
                      sticky=tk.EW)
        btn_submit = ttk.Button(master=frm_login)
        btn_submit.grid(column=1, row=2,
                        sticky=tk.EW)

        errormessage = tk.StringVar()
        lbl_errormessage = ttk.Label(master=frm_login,
                                     textvariable=errormessage)
        lbl_errormessage.grid(column=0, row=3, columnspan=2,
                              sticky=tk.NS)

        for child in frm_login.winfo_children():
            child.grid_configure(padx=3, pady=3)

        frm_login.columnconfigure(0, weight=1)
        frm_login.columnconfigure(1, weight=1)
        frm_login.rowconfigure(0, weight=1)
        frm_login.rowconfigure(1, weight=1)
        frm_login.rowconfigure(2, weight=1)

        # reset Login Frame
        # setting 1 clears password, 2 clears password and username,
        # 3 clears password, username, and error message
        def reset_frm_login(setting):
            if (setting >= 1):
                ent_password.delete(0, tk.END)
            if (setting >= 2):
                ent_username.delete(0, tk.END)
            if (setting >= 3):
                errormessage.set("")

        # handle login/signups
        def handle_accounts():
            username = ent_username.get()
            password = ent_password.get()

            if (username == "" or password == ""):
                errormessage.set("Username and Password cannot be blank")
                return
            elif (btn_submit['text'] == "Login"):
                success = self.accessAccount(username, password)
            elif (btn_submit['text'] == "Sign Up"):
                success = self.createAccount(username, password)
            else:
                return

            if (success == 1):
                errormessage.set("Invalid Username")
                return
            elif(success == 2):
                reset_frm_login(1)
                errormessage.set("Invalid Password")
                return
            else:
                reset_frm_login(3)
                accwin.unbind('<Return>')
                frm_login.grid_remove()
                frm_menu.grid()
                success.display(accwin)

        # handle using enter to submit form
        def handle_enter(event):
            handle_accounts()

        # handle menu navigation
        def handle_menu_nav(option):
            frm_menu.grid_remove()
            frm_login.grid()
            ent_username.focus()
            btn_submit.configure(text=option, command=handle_accounts)
            accwin.bind('<Return>', handle_enter)
        btn_login.configure(command=partial(handle_menu_nav, 'Login'))
        btn_signup.configure(command=partial(handle_menu_nav, 'Sign Up'))

        # handle going back to login/sign up menu
        def handle_back():
            reset_frm_login(3)
            accwin.unbind('<Return>')
            frm_login.grid_remove()
            frm_menu.grid()
        btn_back.configure(command=handle_back)

        accwin.mainloop()
