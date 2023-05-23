#!/usr/bin/env python3
# coding: utf-8

import re
import sys
import json
import time
import common
import getopt
import os.path
import logging
import datetime
import multiprocessing
from git import Repo
from queue import Queue
from threading import Thread
from atlassian.bitbucket import Cloud

# the program's name
program_name = "bitbucket_analyzer"
# the program's version
program_version = "1.0.0"
# config json file
config = {}
# the logger to use throughout the program
logger = logging.getLogger(program_name)
# the compiled regex of file filters
file_filters_re = []
# the compiled regex of content filters
content_filters_re = []


class AnalysisWorker(Thread):
    def __init__(self, queue, unique_id):
        Thread.__init__(self)
        self.queue = queue
        self.unique_id = unique_id

    def run(self):
        while True:
            # gets a task if there are any (which contains an ssh url to the repo)
            (url, name, clones_path, results_path, gitleaks_results_path) = self.queue.get()

            # gets the name of the repo from the url
            clone_path = os.path.abspath(clones_path + name) + "/"

            if not os.path.exists(clone_path):
                # clone the repo
                Repo.clone_from(url, clone_path)
            else:
                # pull the changes
                try:
                    if not config["do_not_update_git"]:
                        repo = Repo(clone_path)
                        repo.git.reset("--hard")
                        repo.remotes.origin.pull()
                except:
                    logger.error("couldn't pull the changes of the repository: {}".format(name))

            log_file_path = "{}{}.log".format(gitleaks_results_path, name)

            if not config["do_not_renew_analysis"] or not os.path.exists(log_file_path):
                # checks for leak using gitleaks and store the logs in a stream
                gitleaks_logs = common.run_gitleaks(clone_path)

                # if the logs are not empty, save them in a file
                # else, remove the file (we have fixed all the leaks)
                if gitleaks_logs:
                    log_file = open(log_file_path, "w")
                    log_file.write(gitleaks_logs)
                    log_file.close()
                elif os.path.exists(log_file_path):
                    os.path.realpath(log_file_path)

                # deserialize the gitleaks logs
                leaks = common.deserialize_gitleaks(log_file_path, file_filters_re, content_filters_re)

                # defines the path of the processed csv file
                processed_log_file_path = "{}{}.csv".format(results_path, name)

                # convert from gitleaks format to csv format
                csv = common.gitleaks_to_csv(leaks, name)

                # load the last generated csv file if it exists to export the comments to te new one
                old_csv = common.deserialize_csv(processed_log_file_path)
                for line in csv:
                    for old_line in old_csv:
                        # if it seems to be the same secret in the same file, we assume they should have the same comment
                        if old_line.comment and line.secret == old_line.secret and line.file == old_line.file:
                            line.comment = old_line.comment
                            break

                # serialize the csv into a file
                common.serialize_csv(processed_log_file_path, csv)

            # notify the queue handler that the task is done
            self.queue.task_done()


def print_help():
    logger.info("usage: {}.py [options...]".format(program_name))
    logger.info("")
    logger.info("you will need to provide at least a workspace, password and username")
    logger.info("you can provide a config file with those information")
    logger.info("")
    logger.info("options:")
    logger.info("\t-c, --config       path of a config file that will be loaded")
    logger.info("\t-s, --save         path to use at the end of the program to save the given configuration")
    logger.info("\t-w, --workspace    bitbucket workspace to analyze")
    logger.info("\t-u, --username     username of your atlassian account")
    logger.info("\t-p, --password     password (or application password for maximum security) of your atlassian account")
    logger.info("\t-o, --output       output path that will be used for cloning and analyzing")
    logger.info("\t-t, --threads      number of threads to use for parallel analysis")
    logger.info("\t-V, --verbose      enables the debug logging mode")
    logger.info("\t-l, --log          name of the log file (it will save every logs of the program)")
    logger.info("\t-h, --help         shows this help message and exits")
    logger.info("\t-v, --version      shows the program's version and exits")


def print_version():
    logger.info("{} version: {}".format(program_name, program_version))


def main(argv):
    global config, file_filters_re, content_filters_re

    save_config_path = ""

    if not common.is_gitleaks_installed():
        logger.critical("gitleaks needs to be installed!")
        sys.exit(1)

    try:
        # getopt is used to define the list of options the program should accept
        opts, args = getopt.getopt(argv, "c:s:w:u:p:o:t:Vl:hv", ["config=", "save=", "workspace=", "username=", "password=", "output=", "threads=", "verbose", "log=", "help", "version"])

        filename = ""
        use_debug_mode = False
        for opt, arg in opts:
            if opt in ("-V", "--verbose"):
                use_debug_mode = True
            elif opt in ("-l", "--log"):
                filename = arg

        # initializes the logging system
        common.initialize_logger(use_debug_mode, filename)

        # first, check for the config file because it has precedence over the other options
        # additionally, help and version also have precedence as they will exit the program
        for opt, arg in opts:
            if opt in ("-h", "--help"):
                print_help()
                sys.exit()
            elif opt in ("-v", "--version"):
                print_version()
                sys.exit()
            elif opt in ("-c", "--config"):
                config_file = open(arg)
                config = json.load(config_file)
                config_file.close()

        # then, check for all other options
        for opt, arg in opts:
            if opt in ("-s", "--save"):
                save_config_path = arg
            elif opt in ("-w", "--workspace"):
                config["workspace"] = arg
            elif opt in ("-u", "--username"):
                config["username"] = arg
            elif opt in ("-p", "--password"):
                config["password"] = arg
            elif opt in ("-o", "--output"):
                config["path"] = arg
            elif opt in ("-t", "--threads"):
                if arg.isnumeric():
                    config["num_threads"] = int(arg)
                else:
                    logger.error("the number of threads must be a numeric value!")

        # checks if the necessary settings have been provided
        if ("workspace" not in config or not config["workspace"]) or \
           ("username" not in config or not config["username"]) or \
           ("password" not in config or not config["password"]):
            print_help()
            sys.exit(1)

    except getopt.GetoptError:
        print_help()
        sys.exit(1)

    # set default values for optional and debug options if they do not exist
    if "do_not_renew_analysis" not in config:
        config["do_not_renew_analysis"] = False
    if "do_not_update_git" not in config:
        config["do_not_update_git"] = False
    if "whitelist" not in config:
        config["whitelist"] = []
    if "blacklist" not in config:
        config["blacklist"] = []
    if "file_filters" not in config:
        config["file_filters"] = []
    if "content_filters" not in config:
        config["content_filters"] = []
    # find the number of thread to use for the multithreading if none is defined (by default, the number of cpu cores
    # for maximum profitability)
    if "num_threads" not in config or not config["num_threads"].isnumeric() or config["num_threads"] <= 0:
        config["num_threads"] = multiprocessing.cpu_count()
    # if no output path was specified, use a predefined value (e.g. "./workspace_2022-11-14_15-19-23/")
    if "path" not in config or not config["path"]:
        config["path"] = "./{}_{}/".format(config["workspace"], datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))
    elif not config["path"].endswith("/"):
        config["path"] += "/"
    # defines the path in which the analysis results will take place
    results_path = config["path"] + "results/"
    gitleaks_results_path = config["path"] + "gitleaks/"
    clones_path = config["path"] + "clones/"

    # connecting  to Atlassian account (either through account password or application password)
    logger.debug("connecting to account...")
    account = Cloud(username=config["username"], password=config["password"])
    logger.info("connected to account: {}".format(config["username"]))

    # loading a given workspace
    logger.debug("connecting to workspace...")
    workspace = account.workspaces.get(config["workspace"])
    logger.info("connected to workspace: {}".format(config["workspace"]))

    # creates the directory in which the analysis will take place if it doesn't exist
    if not os.path.exists(config["path"]):
        os.mkdir(config["path"])
    # creates the directory in which the analysis results will be if it doesn't exist
    if not os.path.exists(results_path):
        os.mkdir(results_path)
    if not os.path.exists(gitleaks_results_path):
        os.mkdir(gitleaks_results_path)
    # creates the directory in which the clones will be if it doesn't exist
    if not os.path.exists(clones_path):
        os.mkdir(clones_path)

    logger.debug("compiling regex filters...")
    for file_filter in config["file_filters"]:
        file_filters_re.append(re.compile(file_filter))
    for content_filter in config["content_filters"]:
        content_filters_re.append(re.compile(content_filter))

    # takes the time before analysis (for statistics)
    time_before_analysis = time.time()

    # creates the queue of repo to analyze by the worker threads
    work_queue = Queue()

    # launch as much worker threads as specified by `num_worker_threads`
    logger.debug("creating worker threads...")
    i = 0
    for x in range(config["num_threads"]):
        worker = AnalysisWorker(work_queue, i)
        worker.daemon = True
        worker.start()
        logger.info("worker thread {} created".format(i))
        i += 1

    # list all repos within the given workspace and add each one to the analysis queue
    logger.debug("adding analysis tasks...")
    for repo in workspace.repositories.each():
        url = repo.get_data("links")["clone"][1]["href"]
        name = url.rsplit('/', 1)[-1][:-4]
        if (len(config["whitelist"]) == 0 or name in config["whitelist"]) and name not in config["blacklist"]:
            work_queue.put((url, name, clones_path, results_path, gitleaks_results_path))

    # wait for all tasks to finish
    work_queue.join()

    # saves the time after analysis and shows the time spent analyzing for statistics
    time_after_analysis = time.time()
    logger.info('time spent analyzing: %.2fs', time_after_analysis - time_before_analysis)

    if save_config_path:
        save_config_file = open(save_config_path, "w")
        save_config_file.write(json.dumps(config, indent=4))
        save_config_file.close()

    # close the atlassian account
    account.close()


if __name__ == "__main__":
    main(sys.argv[1:])
