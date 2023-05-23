#!/usr/bin/env python3
# coding: utf-8

import re
import logging
import os.path
import subprocess


# from: https://stackoverflow.com/questions/14693701/how-can-i-remove-the-ansi-escape-sequences-from-a-string-in-python
def escape_ansi_codes(message):
    return re.compile(r'(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]').sub('', message)


class GitLeak:
    def __init__(self, finding, secret, rule_id, entropy, file, line, fingerprint):
        self.finding = finding
        self.secret = secret
        self.rule_id = rule_id
        self.entropy = entropy
        self.file = file
        self.line = line
        self.fingerprint = fingerprint


def deserialize_gitleaks(path, file_filters_re, content_filters_re):
    leaks = []

    if not os.path.exists(path):
        return leaks

    file = open(path, "r")
    lines = file.readlines()

    # parse gitleaks logs
    if len(lines) > 0:
        i = 0

        while True:
            if i >= len(lines) or not lines[i].startswith("Finding:     "):
                break

            finding = lines[i].partition("Finding:     ")[2]
            i += 1

            while not lines[i].startswith("Secret:      "):
                finding += lines[i]
                i += 1

            finding = finding.rstrip()
            secret = lines[i].partition("Secret:      ")[2]
            i += 1

            while not lines[i].startswith("RuleID:      "):
                secret += lines[i]
                i += 1

            secret = secret.rstrip()
            rule_id = lines[i].partition("RuleID:      ")[2].rstrip()
            entropy = lines[i + 1].partition("Entropy:     ")[2].rstrip()
            file = lines[i + 2].partition("File:        ")[2].rstrip()
            line = lines[i + 3].partition("Line:        ")[2].rstrip()
            fingerprint = lines[i + 4].partition("Fingerprint: ")[2].rstrip()
            i += 6

            should_exclude = False

            # check the file against the file exclusion filters
            for file_filter in file_filters_re:
                if file_filter.search(file):
                    should_exclude = True
                    break

            # check the finding against the content exclusion filters
            for content_filter in content_filters_re:
                if content_filter.search(finding):
                    should_exclude = True
                    break

            # if the leak is not set for exclusion (it seems to be relevant) we add it to the list of leaks
            if not should_exclude:
                leaks.append(GitLeak(finding, secret, rule_id, entropy, file, line, fingerprint))

    return leaks


class LeakCsv:
    def __init__(self, file, line, secret, comment):
        self.file = file
        self.line = line
        self.secret = secret
        self.comment = comment


def deserialize_csv(path):
    csv = []

    if os.path.exists(path):
        processed_log_file = open(path, "r")
        csv_lines = processed_log_file.readlines()

        if len(csv_lines) == 0:
            return csv

        if csv_lines[0].startswith("#"):
            csv_lines.pop(0)

        for csv_line in csv_lines:
            csv_line = csv_line.split(";")

            if len(csv_line) >= 4:
                csv.append(LeakCsv(csv_line[0], csv_line[1], csv_line[2], csv_line[3].rstrip()))

    return csv


def serialize_csv(path, csv, message=""):
    if not path:
        return

    # if the csv is empty, remove it if it exists (we have fixed all the leaks) and return
    if not csv:
        if os.path.exists(path):
            os.remove(path)
        return

    file = open(path, "w")

    if message:
        file.write("# {}\n".format(message))

    max_file_name_len = 0
    max_line_len = 0
    max_secret_len = 0
    for line in csv:
        if len(line.file) > max_file_name_len:
            max_file_name_len = len(line.file)
        if len(line.line) > max_line_len:
            max_line_len = len(line.line)
        if len(line.secret) > max_secret_len:
            max_secret_len = len(line.secret)

    for line in csv:
        file.write(("{:<" + str(max_file_name_len) + "} ;{:<" + str(max_line_len) + "} ;{:<" + str(max_secret_len) + "} ;{}\n").format(line.file, line.line, line.secret.replace(";", "\\;"), line.comment))

    file.close()


def gitleaks_to_csv(leaks, repo_name):
    csv = []

    for leak in leaks:
        formatted_secret = leak.finding.split("\n")[0]

        if len(formatted_secret) > 48:
            formatted_secret = "{}...".format(formatted_secret[:48])

        csv.append(LeakCsv(repo_name + leak.file.split(repo_name)[1], leak.line, formatted_secret, ""))

    return csv


def is_gitleaks_installed():
    # try to run gitleaks as a subprocess
    try:
        subprocess.run(["gitleaks"], stdout=subprocess.DEVNULL)
    except FileNotFoundError:
        return False

    return True


def initialize_logger(use_debug_mode, filename):
    log_level = logging.DEBUG if use_debug_mode else logging.INFO
    log_format = "[%(asctime)s][%(name)s][%(levelname)s] %(message)s"
    logging.basicConfig(level=log_level, format=log_format)

    if filename:
        log_file_handler = logging.FileHandler(filename, "a")
        log_file_handler.setLevel(log_level)
        log_file_handler.setFormatter(logging.Formatter(log_format))
        logging.getLogger().addHandler(log_file_handler)


def run_gitleaks(path):
    return subprocess.run(["gitleaks", "detect", "--no-git", "--verbose", "--config", "filters/gitleaks.toml", "--source", path], stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE).stdout.decode("utf-8")
