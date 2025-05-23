from tkinter import *
from tkinter import filedialog
from File_Scan import MD5_Collect
from API_Referencing import api_call_VT

api_key="insert virustotal API key here"

def open_file():
    filepath = filedialog.askopenfilename(
        title="Select a file",
        filetypes=(("All files", "*.*"),)
    )
    if filepath:
        md5 = MD5_Collect(filepath)
        results= api_call_VT(md5, api_key)

        display_result(results)

def display_result(info):
    result_text.delete("1.0", END)

    if "Error" in info:
        result_text.insert(END, f"Error: {info['Error']}")
    else:
        if info.get("Is it a trojan?") == "Yes":
            result_text.insert(END, "Trojan was found, uh oh")
        for key, value in info.items():
            result_text.insert(END, f"{key}: {value}\n")


# the GUI
root = Tk()
root.title("Malware analysis program")
root.geometry("500x700")

frame = Frame(root)
frame.pack(pady=10)

button = Button(frame, text = "Select File", command=open_file)
button.pack()

result_text = Text(root, wrap=WORD, height=12, width=60)
result_text.pack(pady=10)
root.mainloop()
