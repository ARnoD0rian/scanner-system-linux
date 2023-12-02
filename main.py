from scapy import all as scapy
import socket
import requests
from help import get_service, parametres
from tkinter import ttk
import tkinter as tk
from tkinter.messagebox import showerror, showinfo
from tkinter.simpledialog import askstring
import sys
import pandas as pd
import os

def arp_scan(ip):
    request = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip)
    ans, unans = scapy.srp(request, timeout=2, retry=1)
    result  = "undefinded"

    for sent, received in ans:
        result = received.hwsrc

    return result


def tcp_scan(ip, ports):
    try:
        syn = scapy.IP(dst=ip) / scapy.TCP(dport=ports, flags="S")
    except socket.gaierror:
        raise ValueError('Hostname {} could not be resolved.'.format(ip))

    ans, unans = scapy.sr(syn, timeout=2, retry=1)
    result = []

    for sent, received in ans:
        if received[scapy.TCP].flags == "SA":
            result.append(received[scapy.TCP].sport)

    return result

def get_country_provider(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json?token=394fe6b1d28d1a")
        data = response.json()
        country = data.get("country", "Unknown")
        provider = data.get("org", "Unknown")
        return country, provider
    except Exception as e:
        return "Unknown", "Unknown"

def scan_network(ip_adresses, ports, parametres: parametres):
    print(ip_adresses, ports)
    for ip_address in ip_adresses:
        
        service = list()
        
        open_ports = tcp_scan(ip_address, ports)
        mac_address = arp_scan(ip_address)
        country, provider = get_country_provider(ip_address)
        
        for port in open_ports:
            service = get_service(port)
            parametres.all_information.loc[len(parametres.all_information.index)] = [ip_address, mac_address, country, provider, port, service]
            print([ip_address, mac_address, country, provider, port, service])
        
    parametres.copy()
    

class GUI:
    def __init__(self) -> None:
        
        self.parametres = parametres()
        
        self.ip_directory = ""
        self.ip_diapason = list()
        
        self.root = tk.Tk()
        self.root.title("сетевой сканнер")
        self.root.geometry('1830x1500')
        self.root['background'] = "gray"
        self.root.resizable(True, True)
        
        self.style_frame = ttk.Style()
        self.style_frame.configure("Style.TFrame", background = "gray")
        self.style_check_button = ttk.Style()
        self.style_check_button.configure("TCheckbutton", font=("Arial", 12), background="black", foreground = "black")
        self.style_button = ttk.Style()
        self.style_button.configure("TButton", font=("Arial", 18), background="black", foreground = "black", padding=(10,10,10,10))
        self.style_mini_label = ttk.Style()
        self.style_mini_label.configure("Mini.TLabel", font=("Arial", 12), padding = 5, foreground="black", background="gray")
        self.style_label = ttk.Style()
        self.style_label.configure("TLabel", font=("Arial", 14), padding = 5, foreground="white", background="gray")
        self.style_label_top = ttk.Style()
        self.style_label_top.configure("Top.TLabel", font=("Arial", 18), padding = 10, foreground="white", background="gray")
        
        
        self.main_menu = tk.Menu(self.root)
        
        self.ip_menu = tk.Menu(self.main_menu, tearoff=0)
        self.ip_menu.add_command(label="Диапазон", command=self.input_diapason)
        self.ip_menu.add_separator()
        self.ip_menu.add_command(label="Файл с адресами", command=self.input_directory)
        
        self.filter_menu = tk.Menu(self.main_menu, tearoff=0)
        self.filter_menu.add_command(label="отфильтровать по параметрам", command=self.filter_atributes)
        self.ip_menu.add_separator()
        self.filter_menu.add_command(label="очистить фильтры", command=self.clear_filter)
        
        self.main_menu.add_cascade(label="IP-адреса", menu=self.ip_menu)
        self.main_menu.add_command(label="сохранить порты", command=self.safe_ports)
        self.main_menu.add_cascade(label="фильтрация", menu=self.filter_menu)
        self.main_menu.add_command(label="запуск сканера", command=self.scan_ip)
        self.main_menu.add_command(label="сохранить", command=self.safe_result)
        self.main_menu.add_command(label="Выход", command=self.root.quit)
        
        self.table_Frame = ttk.Frame(self.root, style="Style.TFrame", padding=10)
        self.table_Frame.grid(row=1, column=0, columnspan=2)
        
        self.Scrollbar = ttk.Scrollbar(self.table_Frame)
        self.Scrollbar.grid(row=0, column=2, sticky='ns')

        self.Table = ttk.Treeview(self.table_Frame, yscrollcommand=self.Scrollbar.set, height=60, show="headings")
        self.Table['columns'] = ('IP адрес', 'MAC адрес', 'страна', 'провайдер', 'порт', 'служба')

        for column in ('IP адрес', 'MAC адрес', 'страна', 'провайдер', 'порт', 'служба'):
            self.Table.column(column, width=300)
            self.Table.heading(column, text=column)
        self.Table.column('порт', width=290)

        self.Table.grid(row=0, column=0, columnspan=1, rowspan=2, sticky='nsew')
        self.table_Frame.columnconfigure(0, weight=1)
        self.Table.bind('<Configure>', lambda e: self.Table.configure(height=self.Table.identify_row(e.y)))

        self.Scrollbar.config(command=self.Table.yview)
        
        self.input_ip_Frame = ttk.Frame(self.root, style="Style.TFrame", padding=10)
        self.input_ip_Frame.grid(row=0, column=0)
        
        self.start_ip_Label = ttk.Label(self.input_ip_Frame, text="начальный ip", style="TLabel")
        self.start_ip_Label.grid(column=0, row=0)
        
        self.start_ip_Entry = ttk.Entry(self.input_ip_Frame, justify="center", width=20)
        self.start_ip_Entry.grid(row=1, column=0)
        
        self.end_ip_Label = ttk.Label(self.input_ip_Frame, text="конечный ip", style="TLabel")
        self.end_ip_Label.grid(column=0, row=2)
        
        self.end_ip_Entry = ttk.Entry(self.input_ip_Frame, justify="center", width=20)
        self.end_ip_Entry.grid(row=3, column=0)
                
        self.input_port_Frame = ttk.Frame(self.root, style="Style.TFrame", padding=10)
        self.input_port_Frame.grid(row=0, column=1)
        
        self.start_port_Label = ttk.Label(self.input_port_Frame, text="начальный port", style="TLabel")
        self.start_port_Label.grid(column=0, row=0)
        
        self.start_port_Entry = ttk.Entry(self.input_port_Frame, justify="center", width=20)
        self.start_port_Entry.grid(row=1, column=0)
        
        self.end_port_Label = ttk.Label(self.input_port_Frame, text="конечный port", style="TLabel")
        self.end_port_Label.grid(column=0, row=2)
        
        self.end_port_Entry = ttk.Entry(self.input_port_Frame, justify="center", width=20)
        self.end_port_Entry.grid(row=3, column=0)
        
        self.root.config(menu=self.main_menu)

        self.root.mainloop()
        
    def scan_ip(self):
        self.parametres.scan_ip_adresses.clear()
        self.parametres.clear_information()
        
        with open(self.ip_directory, "r", encoding="utf-8") as file:
            for line in file:
                self.parametres.scan_ip_adresses.append(line[:-1])
        
        scan_network(self.parametres.scan_ip_adresses, self.parametres.scan_ports, self.parametres)
        
        showinfo(title="успешно", message="успех")
        
        self.show()
    
    def input_diapason(self):
        self.ip_directory = "ip_adresses.txt"
        start = list(map(int, self.start_ip_Entry.get().split(".")))
        end = list(map(int, self.end_ip_Entry.get().split(".")))
        
        with open(self.ip_directory, "w", encoding="utf-8") as file:
        
            for i1 in range(start[0], end[0] + 1):
                for i2 in range(start[1], end[1] + 1):
                    for i3 in range(start[2], end[2] + 1):
                        for i4 in range(start[3], end[3] + 1):
                            file.write(f"{i1}.{i2}.{i3}.{i4}\n")
            
        showinfo(title="успешно", message=f"диапазон готов к использованию, если хотите добавить дополнительно IP,\n вы можете их дописать в {self.ip_directory}")
            
    def input_directory(self):
        
        directory = askstring("директория", "введите директорию")
        if os.path.isfile(directory):
            self.ip_directory = directory
        else:
            showerror("такой директории не существует")
            
    def safe_ports(self):
        print("hello")
        start = self.start_port_Entry.get()
        end = self.end_port_Entry.get()
        
        self.parametres.scan_ports.clear()
        for i in range(int(start), int(end)+ 1):
            self.parametres.scan_ports.append(i)
            
        showinfo(title="успех", message="параметры сохранены")
    
    def filter_atributes(self):
        while True:
            atribute = askstring("введите атрибут фильтрации", f"{self.parametres.all_information.columns.tolist()}")
            name_filter = askstring("введите  название", "введите  название переменных через запятую")
            name_filters = name_filter.split(",")
         
            if atribute in self.parametres.all_information.columns.tolist():
                self.parametres.filter_atribute(atribute, name_filters)
                self.show()
                showinfo(title="успешно", message="отфильтровано")
                break
            else:
                showerror(title="ошибка", message="нет такого атрибута")
                
    
    def clear_filter(self):
        self.parametres.copy()
        self.show()
        
    def clear_table(self):
        for i in range(len(self.Table.get_children())):
            self.Table.delete(self.Table.get_children()[0])
    
    def show(self):
        self.clear_table()
        for i in range(len(self.parametres.output)):
            ip_address, mac_address, country, provider, port, service = self.parametres.output.loc[i]
            self.Table.insert("", tk.END, text=f"{i + 1}", values=(ip_address, mac_address, country, provider, port, service))
            
    def safe_result(self):
        directory = askstring("директория", "введите директорию сохранения")
        self.parametres.output.to_csv(f"{directory}", index= False )
        
if __name__ == "__main__":
    gui = GUI()