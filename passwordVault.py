import sqlite3, hashlib
from tkinter import *
from tkinter import simpledialog
from functools import partial


# Database Code
with sqlite3.connect("passwordVault.db") as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL);
""")

window = Tk()
window.title("Password Vault")

def firstScreen():
    window.geometry("350x200")
    lbl = Label(window, text=" Create Enter Password")
    lbl.config(anchor=CENTER)
    lbl.pack()
    txt = Entry(window, width=10)
    txt.pack()
    txt.focus()
    lbl1 = Label(window, text="Re-enter password")
    lbl1.pack()
    txt1 = Entry(window, width=20)
    txt1.pack()
    txt1.focus()
    lbl2 = Label(window)
    lbl2.pack()

    def savePassword():
        if txt.get() == txt1.get():
            hashedPassword = hashPassword(txt.get().encode('utf-8'))
            insert_password = """Insert into masterpassword(password)
             values(?) """
            cursor.execute(insert_password, [(hashedPassword)])
            db.commit()
            passwordVault()
        else:
            lbl2.config(text="Password do not match")

    btn = Button(window, text="Save", command=savePassword)
    btn.pack(pady=5)

def hashPassword(input):
    hash = hashlib.md5(input)
    hash = hash.hexdigest()

    return hash

def loginScreen():
    window.geometry("350x200")
    lbl = Label(window, text="Enter Password")
    lbl.config(anchor=CENTER)
    lbl.pack()
    txt = Entry(window, width=10)
    txt.pack()
    txt.focus()
    lbl1 = Label(window)
    lbl1.pack()

    def getMasterPassword():
        checkHashedPassword = hashPassword(txt.get().encode('utf-8'))
        cursor.execute("Select * FROM masterpassword WHERE id = 1 and password = ?", [(checkHashedPassword)])
        print(checkHashedPassword)
        return cursor.fetchall()

    def checkPassword():
        match = getMasterPassword()
        print(match)



        if match:
            passwordVault()
        else:
            txt.delete(0, 'end')
            lbl1.config(text="wrong")

    btn = Button(window, text="Submit", command=checkPassword)
    btn.pack(pady=5)


def passwordVault():
    for widget in window.winfo_children():
        widget.destroy()
        window.geometry("700x350")

        lbl = Label(window, text="Password Vault")
        lbl.config(anchor=CENTER)
        lbl.pack()


cursor.execute("Select * FROM masterpassword")
if cursor.fetchall():
    loginScreen()
else:
    firstScreen()

window.mainloop()
