from tkinter import *
from tkinter import filedialog
from File_Scan import MD5_Collect
from API_Referencing import api_call_VT

api_key="e2cb60f75bd9d250cc2080ab2937eb5c0e5e8ab9e9d02de8a1679c698230007f"

def open_file():
    filepath = filedialog.askopenfile(
        title="Select a file",
        filetypes=(("All files", "*.*"),)
    )
    if filepath:
        md5 = MD5_Collect(filepath)
        results= api_call_VT(md5)

        display_result(results)

def display_result(info):
    result_text.delete("1.0", END)

    if "Error" in info:
        result_text.inser(END, f"Error: {info['Error']}")
    else:
        for key, value in info.item():
            result_text.inser(END, f"{key}: {value}\n")


# the GUI
root = Tk()
root.title("Malware analysis program")
root.geomertry("500x700")

frame = Frame(root)
frame.pack(pady=10)

button = Button(frame, text = "Select File", command=open_file)
button.pack()

result_text = Text(root, wrap=WORD, height=12, width=60)
result_text.pack(pady=10)
root.mainloop()
