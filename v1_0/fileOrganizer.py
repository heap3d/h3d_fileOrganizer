# ================================
# (C)2021-2023 Dmytro Holub
# heap3d@gmail.com
# --------------------------------
# Python
# EMAG
# Organize rendered images to the specific folders by template
# https://datatofish.com/executable-pyinstaller/
# pip install pyinstaller
# pyinstaller --onefile pythonScriptName.py --windowed

import datetime
import os
import shutil
from os import listdir
from os.path import isfile, join
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog

VERSION = '1.3'
ID_FILE_EXT = 'ext'
ID_NO_FILE_EXT = 'noext'
ID_FRAME_NUM = 'frame'
ID_NO_FRAME_NUM = 'noframe'
ID_HEADER = 'header'
ID_TAIL = 'tail'
ID_BEAUTY = 'Beauty'
ID_REDIRECT = 'redirect'
ID_SUBDIR = 'subdir'
ID_RAW_ALIAS = 'raw_alias'
IDX_ALIAS = 0
IDX_REDIRECT = 1

OLD_COPY_DIR = 'Old'

DIVIDER_CNT = 8
string_preview_size = 128
string_subdir_size = 42


class MainApplication(tk.Frame):
    def __init__(self, parent, *args, **kwargs):
        tk.Frame.__init__(self, parent, *args, **kwargs)
        self.parent = parent
        self.parent.title('Render Files Organizer {}'.format(VERSION))
        self.parent.minsize(790, 515)
        self.frm_main = ttk.Frame(self.parent, padding=10)
        self.frm_main.grid(row=0, column=0, sticky='nsew')

        # grid configure
        tk.Grid.rowconfigure(self.parent, index=0, weight=1)
        tk.Grid.columnconfigure(self.parent, index=0, weight=1)

        tk.Grid.columnconfigure(self.frm_main, index=1, weight=1)

        self.source_dir = tk.StringVar()
        self.frame_length = tk.StringVar()
        self.header_length = tk.StringVar()
        self.use_frame_length = tk.IntVar()
        self.use_header_length = tk.IntVar()
        self.name_space_replace = tk.IntVar()
        self.name_double_underscore = tk.IntVar()
        self.name_space_strip = tk.IntVar()
        self.alias_string = tk.StringVar()
        self.redirect_string = tk.StringVar()

        self.disassembly_dict = dict()
        self.alias_auto_list = list()
        self.alias_custom_list = list()
        self.alias_custom_new_list = list()
        self.alias_custom_remove_list = list()
        self.alias_working_list = list()
        self.rename_header = tk.StringVar()

        self.current_alias_index = 0

        def source_dir_enter_adv(event):
            self.scan_button_command_adv()

        def spin_frame_length_enter(event):
            self.scan_command_message('Frame number processing...', 'Frame number processing complete.')

        def spin_header_length_enter(event):
            self.scan_command_message('Header length processing...', 'Header length processing complete.')

        def listbox_del_adv(event):
            self.scan_command_message('Alias processing...', 'Alias processing complete.')

        def rename_header_enter(event):
            if self.check_rename_header.instate(['selected']):
                self.scan_command_message('Header rename processing...', 'Header rename processing complete.')

        # directory controls
        self.row_dir = 0
        ttk.Label(self.frm_main, text='Directory:').grid(column=0, row=self.row_dir, sticky='e')
        self.edit_dir = ttk.Entry(self.frm_main, textvariable=self.source_dir)
        self.edit_dir.grid(column=1, row=self.row_dir, sticky='new')
        self.source_dir.set(get_start_dir())
        self.edit_dir.bind('<Return>', source_dir_enter_adv)

        self.frm_dir_buttons = ttk.Frame(self.frm_main)
        self.frm_dir_buttons.grid(column=1, row=self.row_dir + 1, pady=10, sticky='ew')
        tk.Grid.columnconfigure(self.frm_dir_buttons, index=0, weight=1)
        tk.Grid.columnconfigure(self.frm_dir_buttons, index=1, weight=1)

        self.btn_browse = ttk.Button(self.frm_dir_buttons, text='Browse...', command=self.browse_button_command_adv)
        self.btn_browse.grid(column=0, row=0, sticky='ew')
        self.btn_scan = ttk.Button(self.frm_dir_buttons, text='Scan Files', command=self.scan_button_command_adv)
        self.btn_scan.grid(column=1, row=0, sticky='ew')

        # custom controls
        self.row_custom = self.row_dir + 2
        ttk.Label(self.frm_main, text='Custom:').grid(column=0, row=self.row_custom, sticky='e')

        self.frm_custom = ttk.Frame(self.frm_main)
        self.frm_custom.grid(column=1, row=self.row_custom, sticky='ew')

        self.frm_lengths = ttk.Frame(self.frm_custom)
        self.frm_lengths.grid(column=0, row=0, sticky='ew')
        self.frm_strings = ttk.Frame(self.frm_custom)
        self.frm_strings.grid(column=1, row=0, sticky='ew')

        self.check_frame_length = ttk.Checkbutton(self.frm_lengths, text='Frame Number Length:')
        init_checkbutton(self.check_frame_length)
        self.spin_frame_length = ttk.Spinbox(self.frm_lengths, width=6, from_=0, to=999999, textvariable=self.frame_length)
        self.frame_length.set('1')
        self.spin_frame_length.bind('<Return>', spin_frame_length_enter)

        self.check_header_length = ttk.Checkbutton(self.frm_lengths, text='Header Length:')
        init_checkbutton(self.check_header_length, False)
        self.spin_header_length = ttk.Spinbox(self.frm_lengths, width=3, from_=0, to=999, textvariable=self.header_length)
        self.header_length.set('0')
        self.spin_header_length.bind('<Return>', spin_header_length_enter)

        self.check_frame_length.grid(column=0, row=0, sticky='ew')
        self.spin_frame_length.grid(column=1, row=0, sticky='ew')
        self.check_header_length.grid(column=2, row=0, padx=(10, 0), sticky='ew')
        self.spin_header_length.grid(column=3, row=0, sticky='ew')

        tk.Grid.columnconfigure(self.frm_custom, index=0, weight=1)
        tk.Grid.columnconfigure(self.frm_custom, index=1, weight=1)

        # string process checkboxes
        self.check_name_space_strip = ttk.Checkbutton(self.frm_strings, text='strip spaces')
        self.check_name_space_strip.config(variable=self.name_space_strip)
        init_checkbutton(self.check_name_space_strip, True)
        self.check_name_double_underscore = ttk.Checkbutton(self.frm_strings, text='double underscore')
        self.check_name_double_underscore.config(variable=self.name_double_underscore)
        init_checkbutton(self.check_name_double_underscore, True)
        self.check_name_space_replace = ttk.Checkbutton(self.frm_strings, text='replace space')
        self.check_name_space_replace.config(variable=self.name_space_replace)
        init_checkbutton(self.check_name_space_replace, True)
        self.check_name_space_strip.grid(column=0, row=0, sticky='ew')
        self.check_name_double_underscore.grid(column=1, row=0, padx=10, sticky='ew')
        self.check_name_space_replace.grid(column=2, row=0, sticky='ew')

        # alias table buttons
        self.frm_alias_buttons = ttk.Frame(self.frm_custom)
        self.frm_alias_buttons.grid(column=0, columnspan=2, row=2, sticky='ew')
        self.btn_replace_alias = ttk.Button(self.frm_alias_buttons, text='Replace Alias', command=self.edit_alias_button_command_adv)
        self.btn_add_alias = ttk.Button(self.frm_alias_buttons, text='Add Alias', command=self.add_alias_button_command_adv)
        self.btn_remove_alias = ttk.Button(self.frm_alias_buttons, text='Remove Alias', command=self.remove_alias_button_command_adv)
        self.btn_clear_custom_edits = ttk.Button(self.frm_alias_buttons, text='Clear Custom Aliases', command=self.clear_custom_aliases_command_adv)
        self.btn_clear_auto_aliases = ttk.Button(self.frm_alias_buttons, text='Clear Auto Aliases', command=self.clear_auto_aliases_button_command_adv)
        self.btn_restore_auto_aliases = ttk.Button(self.frm_alias_buttons, text='Restore Auto Aliases', command=self.restore_auto_aliases_button_command_adv)
        self.btn_replace_alias.grid(column=0, row=0, sticky='ew')
        self.btn_add_alias.grid(column=1, row=0, sticky='ew')
        self.btn_remove_alias.grid(column=2, row=0, sticky='ew')
        self.btn_clear_auto_aliases.grid(column=3, row=0, padx=(10, 0), sticky='ew')
        self.btn_restore_auto_aliases.grid(column=4, row=0, sticky='ew')
        self.btn_clear_custom_edits.grid(column=5, row=0, sticky='ew')

        tk.Grid.columnconfigure(self.frm_alias_buttons, index=0, weight=1)
        tk.Grid.columnconfigure(self.frm_alias_buttons, index=1, weight=1)
        tk.Grid.columnconfigure(self.frm_alias_buttons, index=2, weight=1)
        tk.Grid.columnconfigure(self.frm_alias_buttons, index=3, weight=1)
        tk.Grid.columnconfigure(self.frm_alias_buttons, index=4, weight=1)
        tk.Grid.columnconfigure(self.frm_alias_buttons, index=5, weight=1)

        # alias table controls
        self.row_alias = self.row_custom + 1
        ttk.Label(self.frm_main, text='Alias Table:').grid(column=0, row=self.row_alias, sticky='e')
        self.frm_alias = ttk.Frame(self.frm_main)
        self.frm_alias.grid(column=1, row=self.row_alias, pady=10, sticky='nsew')

        tk.Grid.rowconfigure(self.frm_main, index=self.row_alias, weight=1)
        tk.Grid.rowconfigure(self.frm_alias, index=2, weight=1)
        tk.Grid.columnconfigure(self.frm_alias, index=0, weight=1)
        tk.Grid.columnconfigure(self.frm_alias, index=1, weight=1)

        # alias table entry's
        self.entry_alias = ttk.Entry(self.frm_custom, textvariable=self.alias_string, width=63)
        self.entry_alias.grid(column=0, row=1, pady=10, sticky='ew')
        self.edit_redirect = ttk.Entry(self.frm_custom, textvariable=self.redirect_string, width=63)
        self.edit_redirect.grid(column=1, row=1, sticky='ew')

        # alias table listbox
        self.lbx_alias = tk.Listbox(self.frm_alias, width=64)
        self.lbx_alias.grid(column=0, row=2, sticky='nsew')
        self.lbx_redirect = tk.Listbox(self.frm_alias, width=64)
        self.lbx_redirect.grid(column=1, row=2, sticky='nsew')
        self.lbx_alias.bind('<Delete>', listbox_del_adv)
        self.lbx_redirect.bind('<Delete>', listbox_del_adv)

        # alias table listbox scrollbar
        self.scb_lbx_alias = ttk.Scrollbar(self.frm_alias, command=self.yview)
        self.scb_lbx_alias.grid(column=2, row=2, sticky='ns')
        self.lbx_alias.config(yscrollcommand=self.y_sb_alias)
        self.lbx_redirect.config(yscrollcommand=self.y_sb_redirect)

        def cur_select_alias(event):
            selection_message = self.lbx_alias.curselection()
            if len(selection_message) >= 1:
                self.set_current_alias_index(self.lbx_alias.curselection()[0])
                self.fill_alias_entries(self.get_current_alias_index())

        def cur_select_redirect(event):
            selection_message = self.lbx_redirect.curselection()
            if len(selection_message) >= 1:
                self.set_current_alias_index(self.lbx_redirect.curselection()[0])
                self.fill_alias_entries(self.get_current_alias_index())

        self.lbx_alias.bind('<<ListboxSelect>>', cur_select_alias)
        self.lbx_redirect.bind('<<ListboxSelect>>', cur_select_redirect)

        # rename header controls
        self.row_rename_header = self.row_alias + 3
        self.frm_rename_header = ttk.Frame(self.frm_main)
        self.frm_rename_header.grid(column=1, row=self.row_rename_header, sticky='ew')
        self.check_rename_header = ttk.Checkbutton(self.frm_rename_header, text='Rename Output File Name Header:')
        self.check_rename_header.grid(column=0, row=0, sticky='w')
        init_checkbutton(self.check_rename_header, False)
        self.edit_rename_header = ttk.Entry(self.frm_rename_header, textvariable=self.rename_header)
        self.edit_rename_header.grid(column=1, row=0, sticky='we')
        tk.Grid.columnconfigure(self.frm_rename_header, index=1, weight=1)
        self.edit_rename_header.bind('<Return>', rename_header_enter)

        # add file names preview
        self.row_preview = self.row_rename_header + 1
        ttk.Label(self.frm_main, text='Preview:').grid(column=0, row=self.row_preview, sticky='e')
        self.frm_preview = ttk.Frame(self.frm_main)
        self.frm_preview.grid(column=1, row=self.row_preview, pady=10, sticky='nsew')
        self.lbx_preview_subdir = tk.Listbox(self.frm_preview, width=string_subdir_size, justify=tk.RIGHT)
        self.lbx_preview = tk.Listbox(self.frm_preview, width=string_preview_size - string_subdir_size)
        self.lbx_preview_subdir.grid(column=0, row=0, sticky='nsew')
        self.lbx_preview.grid(column=1, row=0, sticky='nsew')

        tk.Grid.rowconfigure(self.frm_main, index=self.row_preview, weight=10)
        tk.Grid.rowconfigure(self.frm_preview, index=0, weight=1)
        tk.Grid.columnconfigure(self.frm_preview, index=1, weight=1)

        # preview scrollbar
        self.scb_lbx_preview = ttk.Scrollbar(self.frm_preview, command=self.preview_yview)
        self.scb_lbx_preview.grid(column=2, row=0, sticky='ns')
        self.lbx_preview.config(yscrollcommand=self.y_sb_preview)
        self.lbx_preview_subdir.config(yscrollcommand=self.y_sb_preview_subdir)

        # move button
        self.row_move = self.row_preview + 1
        self.frm_move = ttk.Frame(self.frm_main)
        self.frm_move.grid(column=1, row=self.row_move, sticky='ew')
        self.btn_copy = ttk.Button(self.frm_move, text='Copy Files', command=self.copy_files_cmd)
        self.btn_copy.grid(column=0, row=0, sticky='ew')
        self.btn_move = ttk.Button(self.frm_move, text='Move Files', command=self.move_files_cmd)
        self.btn_move.grid(column=1, row=0, sticky='ew')

        tk.Grid.columnconfigure(self.frm_move, index=0, weight=1)
        tk.Grid.columnconfigure(self.frm_move, index=1, weight=1)

        # status controls
        self.row_status = self.row_move + 1
        ttk.Label(self.frm_main, text='Status:').grid(column=0, row=self.row_status, sticky='e')
        self.lbl_status = ttk.Label(self.frm_main, text='Ready')
        self.lbl_status.grid(column=1, row=self.row_status)

        # init live action for controls
        self.check_frame_length.config(command=self.check_frame_length_cmd)
        self.check_header_length.config(command=self.check_header_length_cmd)
        self.check_name_space_strip.config(command=self.check_name_space_strip_cmd)
        self.check_name_double_underscore.config(command=self.check_name_double_underscore_cmd)
        self.check_name_space_replace.config(command=self.check_name_space_replace_cmd)
        self.check_rename_header.config(command=self.check_rename_header_cmd)

    def check_rename_header_cmd(self):
        self.scan_command_message('Header rename processing...', 'Header rename processing complete.')

    def check_name_space_strip_cmd(self):
        self.scan_command_message('Strip spaces processing...', 'Strip spaces processing complete.')

    def check_name_double_underscore_cmd(self):
        self.scan_command_message('Double underscore processing...', 'Double underscore processing complete.')

    def check_name_space_replace_cmd(self):
        self.scan_command_message('Replace space processing...', 'Replace space processing complete.')

    def check_frame_length_cmd(self):
        self.scan_command_message('Frame number processing...', 'Frame number processing complete.')

    def check_header_length_cmd(self):
        self.scan_command_message('Header length processing...', 'Header length processing complete.')

    def clear_alias_entries(self):
        self.alias_string.set('')
        self.redirect_string.set('')

    def fill_alias_entries(self, idx):
        if idx == '':
            return
        self.alias_string.set(self.lbx_alias.get(idx))
        self.redirect_string.set(self.lbx_redirect.get(idx))

    def y_sb_alias(self, *args):
        if self.lbx_alias.yview() != self.lbx_redirect.yview():
            self.lbx_redirect.yview_moveto(args[0])
        self.scb_lbx_alias.set(*args)

    def y_sb_redirect(self, *args):
        if self.lbx_alias.yview() != self.lbx_redirect.yview():
            self.lbx_alias.yview_moveto(args[0])
        self.scb_lbx_alias.set(*args)

    def y_sb_preview(self, *args):
        if self.lbx_preview.yview() != self.lbx_preview_subdir.yview():
            self.lbx_preview_subdir.yview_moveto(args[0])
        self.scb_lbx_preview.set(*args)

    def y_sb_preview_subdir(self, *args):
        if self.lbx_preview_subdir.yview() != self.lbx_preview.yview():
            self.lbx_preview.yview_moveto(args[0])
        self.scb_lbx_preview.set(*args)

    def yview(self, *args):
        self.lbx_alias.yview(*args)
        self.lbx_redirect.yview(*args)

    def preview_yview(self, *args):
        self.lbx_preview_subdir.yview(*args)
        self.lbx_preview.yview(*args)

    def browse_button_command_adv(self):
        self.source_dir.set(get_dir_path(self.source_dir.get()))
        self.scan_button_command_adv()

    def clear_auto_aliases_button_command_adv(self):
        #  clear auto aliases command advanced, DELETE ALL ALIAS AUTO LIST ROWS BY REMOVE ALIAS ADVANCED
        for alias_auto_pair_row in self.alias_auto_list:
            self.remove_alias_adv(alias_auto_pair_row)
        self.scan_command_message('Clearing auto aliases...', 'Clearing auto aliases complete.')

    def restore_auto_aliases_button_command_adv(self):
        #  restore auto aliases command advanced
        for alias_auto_pair_row in self.alias_auto_list:
            self.add_alias_adv(alias_auto_pair_row)
        self.scan_command_message('Restoring auto aliases...', 'Restoring auto aliases complete.')

    def clear_custom_aliases_command_adv(self):
        #  clear custom aliases command advanced
        self.alias_custom_remove_list.clear()
        self.alias_custom_new_list.clear()
        self.scan_command_message('Clearing custom aliases...', 'Clearing custom aliases complete.')

    def add_alias_button_command_adv(self):
        #  add alias button command advanced
        self.add_alias_adv(self.get_new_alias_edits())
        self.scan_command_message('Adding auto aliases...', 'Adding auto aliases complete.')

    def add_alias_adv(self, alias_pair_row):
        if alias_pair_row is None:
            return
        if len(alias_pair_row) == 0:
            return
        if alias_pair_row[IDX_ALIAS] == '' or alias_pair_row[IDX_REDIRECT] == '':
            return
        if alias_pair_row in self.alias_custom_remove_list:
            self.alias_custom_remove_list.remove(alias_pair_row)
        elif alias_pair_row not in self.alias_custom_new_list:
            if alias_pair_row not in self.alias_auto_list:
                self.alias_custom_new_list.append(alias_pair_row)

    def get_new_alias_edits(self):
        # get new alias edits
        alias = self.entry_alias.get()
        redirect = self.redirect_string.get()
        if alias == '' or redirect == '':
            return ['', '']
        return [alias, redirect]

    def remove_alias_button_command_adv(self):
        # remove alias button command advanced
        self.remove_alias_adv(self.get_current_alias_adv())
        self.scan_command_message('Removing alias...', 'Removing alias complete.')

    def remove_alias_adv(self, alias_pair_row):
        if alias_pair_row is None:
            return
        if len(alias_pair_row) == 0:
            return
        if alias_pair_row[IDX_ALIAS] == '' or alias_pair_row[IDX_REDIRECT] == '':
            return
        if alias_pair_row in self.alias_custom_new_list:
            self.alias_custom_new_list.remove(alias_pair_row)
        elif alias_pair_row not in self.alias_custom_remove_list:
            self.alias_custom_remove_list.append(alias_pair_row)

    def edit_alias_button_command_adv(self):
        # edit alias button command advanced
        # get new edits
        new_alias_pair_row = self.get_new_alias_edits()
        if new_alias_pair_row is None:
            return
        if len(new_alias_pair_row) == 0:
            return
        if new_alias_pair_row[IDX_ALIAS] == '' or new_alias_pair_row[IDX_REDIRECT] == '':
            return
        # delete current row
        self.remove_alias_adv(self.get_current_alias_adv())
        # add new row
        self.add_alias_adv(new_alias_pair_row)
        self.scan_command_message('Processing alias...', 'Processing alias complete.')

    def get_current_alias_adv(self):
        if self.get_current_alias_index() > len(self.alias_working_list) - 1:
            return ['', '']
        return self.alias_working_list[self.get_current_alias_index()]

    def set_current_alias_index(self, index):
        valid_index = index
        if index < 0:
            valid_index = 0
        if index >= len(self.alias_working_list):
            valid_index = len(self.alias_working_list) - 1
        if index == 0:
            valid_index = 0
        self.current_alias_index = valid_index

    def get_current_alias_index(self):
        if self.current_alias_index < 0:
            self.set_current_alias_index(0)
        if self.current_alias_index >= len(self.alias_working_list):
            self.set_current_alias_index(len(self.alias_working_list) - 1)
        return self.current_alias_index

    def scan_button_command_adv(self):
        self.scan_command_message('Scanning...', 'Scanning complete.')

    def scan_command_message(self, start_message, finish_message):
        # get source dir
        if not os.path.exists(self.source_dir.get()):
            self.set_status('Enter valid directory path to scan.')
            return  # return if source dir is not valid
        self.set_status(start_message)
        # get list of filenames in specific directory
        filename_list = self.get_file_list_adv(self.source_dir.get())

        # scan file list
        self.scan_file_list_adv(filename_list)

        self.refresh_tables_adv()
        self.set_status(finish_message)

    def scan_file_list_adv(self, input_filename_list):
        # scan input file list
        self.disassembly_dict = dict()
        # get disassembly_dict for full input filename list
        alias_auto_full_list, disassembly_table_auto_full_dict = self.generate_disassembly_dict(input_filename_list)
        # get alias manual list for file list, filter file list
        processed_manual_filename_list = list()
        not_processed_filename_list = list(input_filename_list)
        for alias_manual_row in self.alias_custom_new_list:
            manual_filename_list = list(not_processed_filename_list)
            for filename in manual_filename_list:
                if alias_manual_row[IDX_ALIAS] not in filename:
                    continue
                disassembly_row = {ID_RAW_ALIAS: alias_manual_row[IDX_ALIAS]}
                self.disassembly_dict[filename] = disassembly_row
                not_processed_filename_list.remove(filename)
                processed_manual_filename_list.append(filename)
        # copy disassembly dict data from alias auto full list to alias manual filename list entries
        for filename in self.disassembly_dict:
            self.disassembly_dict[filename][ID_FILE_EXT] = disassembly_table_auto_full_dict[filename][ID_FILE_EXT]
            self.disassembly_dict[filename][ID_NO_FILE_EXT] = disassembly_table_auto_full_dict[filename][ID_NO_FILE_EXT]
            self.disassembly_dict[filename][ID_FRAME_NUM] = disassembly_table_auto_full_dict[filename][ID_FRAME_NUM]
            self.disassembly_dict[filename][ID_NO_FRAME_NUM] = disassembly_table_auto_full_dict[filename][ID_NO_FRAME_NUM]

        # generate alias auto data for not processed filename list
        processed_filename_list = list()
        # get disassembly_dict for not processed filename list
        self.alias_auto_list, disassembly_table_auto_dict = self.generate_disassembly_dict(not_processed_filename_list)
        for alias_auto_pair_row in self.alias_auto_list:
            auto_filename_list = list(disassembly_table_auto_dict)
            for filename in auto_filename_list:
                if alias_auto_pair_row[IDX_ALIAS] == disassembly_table_auto_dict[filename][ID_NO_FRAME_NUM]:
                    # ignore deleted alias stored in alias custom remove list
                    if alias_auto_pair_row in self.alias_custom_remove_list:
                        continue
                    disassembly_table_auto_dict[filename][ID_RAW_ALIAS] = alias_auto_pair_row[IDX_ALIAS]
                    not_processed_filename_list.remove(filename)
                    processed_filename_list.append(filename)

        # get self.disassembly_dict
        for filename in disassembly_table_auto_dict:
            if filename in processed_filename_list:
                self.disassembly_dict[filename] = disassembly_table_auto_dict[filename]
        self.alias_working_list = self.get_alias_working_list_adv()

        self.update_disassembly_dict_adv(processed_manual_filename_list + processed_filename_list)

    def update_disassembly_dict_adv(self, input_filename_list):
        # update disassembly dictionary advanced
        for alias_string_pair in self.alias_working_list:
            redirect_subdir = process_string_spaces(
                f'{alias_string_pair[IDX_REDIRECT]}',
                space_strip=self.name_space_strip.get(),
                double_underscore=self.name_double_underscore.get(),
                space_replace=self.name_space_replace.get()
            )
            filename_list = list(input_filename_list)
            for filename in filename_list:
                # compare by raw alias
                if alias_string_pair[IDX_ALIAS] == self.disassembly_dict[filename][ID_RAW_ALIAS]:
                    # redirect_noframe = self.disassembly_dict[filename][ID_NO_FRAME_NUM]
                    redirect_noframe = process_string_spaces(
                        f'{self.disassembly_dict[filename][ID_NO_FRAME_NUM]}',
                        space_strip=self.name_space_strip.get(),
                        double_underscore=self.name_double_underscore.get(),
                        space_replace=self.name_space_replace.get()
                    )
                    # process rename header field
                    if not self.check_rename_header.instate(['selected']):
                        redirect_filename = f'{redirect_subdir}/{redirect_noframe}_{self.disassembly_dict[filename][ID_FRAME_NUM]}{self.disassembly_dict[filename][ID_FILE_EXT]}'
                    else:
                        modified_header = self.rename_header.get()
                        if modified_header is None or modified_header == '':
                            modified_header = redirect_noframe
                            redirect_modified_noframe = modified_header
                        else:
                            if redirect_subdir != ID_BEAUTY:
                                redirect_modified_noframe = '{}_{}'.format(modified_header, redirect_subdir)
                            else:
                                redirect_modified_noframe = modified_header
                        redirect_filename = f'{redirect_subdir}/{redirect_modified_noframe}_{self.disassembly_dict[filename][ID_FRAME_NUM]}{self.disassembly_dict[filename][ID_FILE_EXT]}'
                    # add processed filenames to self.disassembly_dict
                    self.disassembly_dict[filename][ID_SUBDIR] = redirect_subdir
                    self.disassembly_dict[filename][ID_REDIRECT] = redirect_filename

    def refresh_tables_adv(self):
        # clear alias entries
        self.clear_alias_entries_adv()
        # refresh alias table
        self.refresh_alias_table_adv()
        # refresh redirect table
        self.refresh_redirect_table_adv()
        # refresh preview table
        self.refresh_preview_table_adv()
        # refresh preview subdir table
        self.refresh_preview_subdir_table_adv()

    def clear_alias_entries_adv(self):
        self.alias_string.set('')
        self.redirect_string.set('')

    def refresh_alias_table_adv(self):
        self.lbx_alias.delete(0, tk.END)  # clear alias listbox
        for alias in self.alias_working_list:
            self.lbx_alias.insert(tk.END, alias[IDX_ALIAS])

    def refresh_redirect_table_adv(self):
        self.lbx_redirect.delete(0, tk.END)  # clear redirect list
        for alias in self.alias_working_list:
            redirect_string = process_string_spaces(
                alias[IDX_REDIRECT],
                space_strip=self.name_space_strip.get(),
                double_underscore=self.name_double_underscore.get(),
                space_replace=self.name_space_replace.get()
            )
            self.lbx_redirect.insert(tk.END, redirect_string)

    def refresh_preview_table_adv(self):
        # clear preview list
        self.lbx_preview.delete(0, tk.END)
        for filename in sorted(self.disassembly_dict):
            preview_string = self.disassembly_dict[filename][ID_REDIRECT]
            preview_string = os.path.basename(preview_string)
            preview_string = process_string_spaces(
                preview_string,
                space_strip=self.name_space_strip.get(),
                double_underscore=self.name_double_underscore.get(),
                space_replace=self.name_space_replace.get()
            )
            self.lbx_preview.insert(tk.END, preview_string)

    def refresh_preview_subdir_table_adv(self):
        # clear preview subdir list
        self.lbx_preview_subdir.delete(0, tk.END)
        if len(self.disassembly_dict) == 0:
            return
        maxlength = 5 + len(
            max(
                list(
                    map(
                        lambda x: self.disassembly_dict[x][ID_SUBDIR],
                        list(self.disassembly_dict)
                    )
                ),
                key=len)
        )
        self.lbx_preview_subdir.config(width=maxlength)
        self.lbx_preview.config(width=(string_preview_size - maxlength))
        for filename in sorted(self.disassembly_dict):
            preview_string = self.disassembly_dict[filename][ID_REDIRECT]
            preview_string = os.path.dirname(preview_string)
            preview_string = process_string_spaces(
                preview_string,
                space_strip=self.name_space_strip.get(),
                double_underscore=self.name_double_underscore.get(),
                space_replace=self.name_space_replace.get()
            )
            self.lbx_preview_subdir.insert(tk.END, preview_string)

    def get_alias_working_list_adv(self):
        # combine alias auto list, alias custom remove list, alias custom new list
        alias_working_list = list(self.alias_auto_list)
        for alias in self.alias_custom_remove_list:
            if alias in alias_working_list:
                alias_working_list.remove(alias)
        for alias in self.alias_custom_new_list:
            if alias not in alias_working_list:
                alias_working_list.insert(0, alias)
        return alias_working_list

    def get_file_list_adv(self, dir_path):
        file_list = [f for f in listdir(dir_path) if isfile(join(dir_path, f))]
        return file_list

    def generate_disassembly_dict(self, file_list):
        if len(file_list) < 1:
            return [list(), dict()]
        # get working list in case of multiple file list with different templates
        dir_path = self.source_dir.get()
        filename_parts = dict()
        disassembly_table_dict = dict()
        working_list = list(file_list)
        stat = dict()
        if not self.check_header_length.instate(['selected']):
            working_letter = ''
            working_letter_count = 0
            for item in working_list:  # initialize list
                stat[item[0]] = 0
            for item in working_list:  # count of appearance for fist letters in filename
                stat[item[0]] += 1
            for letter in stat:  # choose pattern with larger appearance count
                if stat[letter] > working_letter_count:
                    working_letter = letter
                    working_letter_count = stat[letter]
            for item in file_list:  # remove item if not match working pattern
                if item[0] != working_letter:
                    working_list.remove(item)
        else:
            compare_idx = 0
            loop_stop = False
            compare_set = set()
            while not loop_stop:
                compare_set.clear()
                stat.clear()
                # initialize stat dictionary
                for filename in working_list:
                    file_ext = get_file_ext(join(dir_path, filename))[1]
                    filename_noext = filename[:-len(file_ext)]
                    frame_num_detect = self.get_frame_number(filename_noext)
                    filename_noframe = frame_num_detect[1]
                    stat[filename_noframe[:(compare_idx + 1)]] = 0
                # count appearance of compare string
                for filename in working_list:
                    file_ext = get_file_ext(join(dir_path, filename))[1]
                    filename_noext = filename[:-len(file_ext)]
                    frame_num_detect = self.get_frame_number(filename_noext)
                    filename_noframe = frame_num_detect[1]
                    compare_str = filename_noframe[:(compare_idx + 1)]
                    stat[compare_str] += 1
                    compare_set.add(compare_str)
                    if compare_idx >= len(filename) - 1:
                        loop_stop = True
                if len(compare_set) > 1:
                    loop_stop = True
                compare_idx += 1

            # get most used working string
            most_used_working_str_count = 0
            most_used_working_str = ''
            for compare_str in compare_set:
                if stat[compare_str] > most_used_working_str_count:
                    most_used_working_str_count = stat[compare_str]
                    most_used_working_str = compare_str
            for filename in file_list:
                file_ext = get_file_ext(join(dir_path, filename))[1]
                filename_noext = filename[:-len(file_ext)]
                frame_num_detect = self.get_frame_number(filename_noext)
                filename_noframe = frame_num_detect[1]
                # check if working list strings has the same length
                if all((lambda x: len(x) == len(working_list[0]), working_list)):
                    if not filename_noframe.startswith(most_used_working_str):
                        working_list.remove(filename)
                else:
                    if not filename_noframe == most_used_working_str:
                        working_list.remove(filename)

        for filename in working_list:
            # detect file extension
            filename_parts[ID_FILE_EXT] = get_file_ext(join(dir_path, filename))[1]
            # cutoff file extension
            filename_parts[ID_NO_FILE_EXT] = filename[:-len(filename_parts[ID_FILE_EXT])]
            # detect frame number
            frame_num_detect = self.get_frame_number(filename_parts[ID_NO_FILE_EXT])
            filename_parts[ID_FRAME_NUM] = frame_num_detect[0]
            filename_parts[ID_NO_FRAME_NUM] = frame_num_detect[1]

            # store file extension, filename no extension, frame number, filename no frame in disassembly_table_dict
            disassembly_table_dict[filename] = dict(filename_parts)

        # store filename no frame in the list to later sort
        name_noframe_list = list()
        for filename in disassembly_table_dict:
            name_noframe_list.append(disassembly_table_dict[filename][ID_NO_FRAME_NUM])

        alias_auto_dict = self.get_alias_auto_dict(name_noframe_list)

        key_list = list()
        for key in alias_auto_dict:
            key_list.append(key)
        key_list.sort(key=len, reverse=True)

        return_alias_list = list()
        for key in key_list:
            alias = key
            redirect = alias_auto_dict[key].strip(' _')  # strip string to avoid string like '_'
            if redirect == '':
                redirect = ID_BEAUTY
            return_alias_list.append([alias, redirect])
        return [return_alias_list, disassembly_table_dict]

    def set_status(self, input_string):
        self.lbl_status.config(text=input_string)
        tk.Tk.update(self)

    def copy_files_cmd(self):
        self.process_files_command_adv(copy_files=True)

    def move_files_cmd(self):
        self.process_files_command_adv(copy_files=False)

    def process_files_command_adv(self, copy_files):
        # move files command advanced
        if copy_files:
            self.set_status('Copying files...')
        else:
            self.set_status('Moving files...')
        for filename in self.disassembly_dict:
            # create subdir
            subdir_string = process_string_spaces(
                self.disassembly_dict[filename][ID_SUBDIR],
                space_strip=self.name_space_strip.get(),
                double_underscore=self.name_double_underscore.get(),
                space_replace=self.name_space_replace.get()
            )
            target_redirect_subdir = os.path.join(self.source_dir.get(), subdir_string)
            os.makedirs(name=target_redirect_subdir, exist_ok=True)
            # move file, make new name, create copy of old files
            source_fullpath = os.path.join(self.source_dir.get(), filename)
            redirect_string = process_string_spaces(
                self.disassembly_dict[filename][ID_REDIRECT],
                space_strip=self.name_space_strip.get(),
                double_underscore=self.name_double_underscore.get(),
                space_replace=self.name_space_replace.get()
            )
            target_fullpath = os.path.join(self.source_dir.get(), redirect_string)
            # check if file already exist
            if os.path.exists(target_fullpath):
                target_dirname, target_filename = os.path.split(target_fullpath)
                old_copy_dirname = get_old_copy_dirname(target_dirname)
                # create old copy subdir
                os.makedirs(name=old_copy_dirname, exist_ok=True)
                old_copy_fullpath = os.path.join(old_copy_dirname, target_filename)
                # move file to old copy dir
                os.rename(target_fullpath, old_copy_fullpath)
            if copy_files:
                # copy files to a new location
                shutil.copy(source_fullpath, target_fullpath)
            else:
                # move source file to a new location
                os.rename(source_fullpath, target_fullpath)
        if copy_files:
            self.scan_command_message('Copying files...', 'Copying files complete.')
        else:
            self.scan_command_message('Moving files...', 'Moving files complete.')

    def get_alias_auto_dict(self, input_name_list):
        if input_name_list is None:
            return dict()
        if len(input_name_list) == 0:
            return dict()
        working_set = set(input_name_list)
        check_set = set()

        return_dict = dict()

        # get length of the longest element
        longest_len = len(max(working_set, key=len))

        index = 0
        loop_stop = False
        for i in range(longest_len):
            if loop_stop:
                break
            index = i
            check_set.clear()
            for item in working_set:
                if i >= (len(item) - 1):
                    loop_stop = True
                check_set.add(item[i])
            if len(check_set) > 1:
                break
        if index < 0:
            return dict()  # return void return_list

        if len(check_set) == 1:
            index += 1

        # if checked : get header length from spinner
        if self.check_header_length.instate(['selected']):
            index = int(self.header_length.get())

        for filename_no_frame_string in working_set:
            return_dict[filename_no_frame_string] = filename_no_frame_string[index:]

        return return_dict

    def get_frame_number(self, input_string):
        num_finish = len(input_string)

        idx = num_finish
        while idx >= 0:
            if input_string[idx - 1].isdigit():
                num_finish = idx
                break
            idx -= 1

        num_start = num_finish
        idx = num_start
        while idx >= 0:
            if not input_string[idx - 1].isdigit():
                num_start = idx
                break
            idx -= 1

        # if check_frame_number: use frame_number_length
        if self.check_frame_length.instate(['selected']):
            num_start = max(num_start, num_finish - int(self.frame_length.get()))

        if idx < 0:
            num_start = 0

        str_part1 = input_string[:num_start]
        frame_num = input_string[num_start:num_finish]
        if self.check_frame_length.instate(['selected']):
            frame_num = frame_num.zfill(int(self.frame_length.get()))  # fill number with leading zeros
        str_part2 = input_string[num_finish:]
        str_noframe = str_part1 + str_part2

        return [frame_num, str_noframe]


def get_file_ext(full_filename):
    return os.path.splitext(full_filename)


def get_dir_path(source_dir):
    result = filedialog.askdirectory(initialdir=source_dir, title='Select Folder with Rendered Images')
    if result != '':
        return result
    return source_dir


def get_start_dir():
    path_debug = r'F:\work\scenes\kostya_shemelin\20220318_Post_fix\Renders\Frames\PartPartch_OP10Cam10_1 - Copy'
    if os.path.exists(path_debug):
        return path_debug
    return os.path.dirname(os.path.realpath(__file__))


def init_checkbutton(checkbutton, value=False):
    if checkbutton.instate(['selected']) != value:
        checkbutton.invoke()
    else:
        # on|off to reinitialize
        checkbutton.invoke()
        checkbutton.invoke()


def process_string_spaces(input_string, space_strip=False, double_underscore=False, space_replace=False):
    if input_string == '':
        return ''
    modified_string = input_string
    if space_strip:
        modified_string = modified_string.strip(' _')
    if double_underscore:
        modified_string = modified_string.replace('__', '_')
    if space_replace:
        modified_string = modified_string.replace(' ', '_')

    return modified_string


def get_old_copy_dirname(target_dirname):
    now = datetime.datetime.now()
    time_suffix = now.strftime('%Y%m%d_%H%M%S')
    subdir_name = f'_{OLD_COPY_DIR}_{time_suffix}'
    old_copy_dirname = os.path.join(target_dirname, subdir_name)
    return old_copy_dirname


def main():
    root = tk.Tk()
    MainApplication(root)
    root.mainloop()


if __name__ == '__main__':
    main()
