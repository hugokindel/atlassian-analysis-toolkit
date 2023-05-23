# Atlassian Sensitive Data Analysis Toolkit

A set of tools to analyze internal services to discover sensitive data such as password, tokens and API keys for auditing purposes.  
Disclaimer: This project is useful fo automated analysis of Confluence, Jira or a Bitbucket workspace. But if the goal is to analyze only one repository other tools can yield better results, like this [one](https://github.com/aws-samples/automated-security-helper).

## Features

- Downloading and analysis of data from the following services:
    - Bitbucket through cloning and pulling of every git repositories of a given workspace.
    - Confluence by downloading each pages from all spaces of a given domain.
    - Jira by downloading each issues from all projects, including their description and comments.
- Configurable:
    - Through the CLI interface.
    - Through a JSON file containing the configuration to execute.
- Multithreading through a task queue used by multiple worker threads.
- Whitelist and blacklist support to ensure only the necessary sources are analyzed.
- Filename filters and content filters to remove false positive or unwanted results.
- Keep track of your audits through comments that will be reimported when reanalyzing a source.

## How to use

### Install dependencies

Make sure [Python 3](https://www.python.org) is installed.

#### macOS

- Install [brew](https://brew.sh) (package manager).
- Install all the dependencies: `brew install gitleaks && pip3 install atlassian-python-api GitPython`

#### Linux and Windows

- Download a precompiled version of [Gitleaks](https://github.com/zricethezav/gitleaks/releases) and add it to your path.
- Install the remaining dependencies: `pip install atlassian-python-api GitPython`

### Run the program

#### Bitbucket Analyzer

- Open a terminal in this folder.
- Run the following command `./bitbucket_analyzer.py -h` to know how to use the program.

#### Confluence Analyzer

- Open a terminal in this folder.
- Run the following command `./confluence_analyzer.py -h` to know how to use the program.

#### Jira Analyzer

- Open a terminal in this folder.
- Run the following command `./jira_analyzer.py -h` to know how to use the program.

## Dependencies

- [Gitleaks](https://github.com/zricethezav/gitleaks): Analysis of data.
- [GitPython](https://github.com/gitpython-developers/GitPython): Cloning and pulling of git repositories.
- [atlassian-python-api](https://github.com/atlassian-api/atlassian-python-api): API to communicate with Atlassian's services.
