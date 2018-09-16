This is a quick-start guide for new developers and **not** meant to be an exhaustive `git`/`GitLab` tutorial, in any way.

## `git` Setup
You only need to do this once.
1. Tell `git` your name:

    `$ git config --global user.name "<Firstname> <Lastname>"`
2. Tell `git` your email address:

    `$ git config --global user.email <youremail@domain.com>`

## `wget2` Setup
You only need to do this once.
1. Fork the [upstream](https://gitlab.com/gnuwget/wget2) via GitLab interface
2. Clone your fork:

    `$ git clone https://gitlab.com/<your username>/wget2.git; cd wget2`

3. Add upstream repository:

    `$ git remote add upstream https://gitlab.com/gnuwget/wget2.git`
4. Build `wget2` as explained in [README](https://gitlab.com/gnuwget/wget2/blob/master/README.md)

## Development
You'll do this periodically.  :)
1. Pick an issue from [Issues](https://gitlab.com/gnuwget/wget2/issues) or
2. [Create new issue](https://gitlab.com/gnuwget/wget2/issues/new) if you want to add a new feature
3. For said issue/feature create a new branch:

    `$ git checkout -b <branch_name>`
4. Make your changes using IDE/text editor of your choice. Follow [kernel coding style](https://github.com/torvalds/linux/blob/master/Documentation/process/coding-style.rst) while doing so
5. Confirm your changes by building `wget2` as explained in [README](https://gitlab.com/gnuwget/wget2/blob/master/README.md)
   Sample build:

        $ ./bootstrap
        $ ./configure --enable-manywarnings --disable-silent-rules --enable-assert
        $ make check
6. `git add` and `git commit` your changes:

    `$ git add <modified_files>`
    `$ git commit`
7. Push your changes to your fork:

    `$ git push origin <branch_name>`
8. Create a Merge Request (https://gitlab.com/\<gitlab_username\>/wget2/merge_requests/new) to merge your changes with the [upstream](https://gitlab.com/gnuwget/wget2)
9. Repeat steps 4, 5, 6 & 7 if more changes are requested.
Since you are working on your own repository called 'origin', feel free to make any changes to your branch.
You may delete and change commits like you want and then pushing them to GitLab with `git push -f`. This overwrites the history there as well - and that is what you want. If you already made a Merge Request (MR), GitLab will automatically update it for you. There is no need to close a MR and open a new one. Even the Continuous Integration (CI) will start again with your changes.

10. Delete the local branch and remote branch once your changes get merged:

    `$ git branch -d <branch_name>`
    `$ git push origin --delete <branch_name>`
11. Go to step 1

## Syncing Your Fork
You need to do this periodically.
1. Fetch code from upstream:

    `$ git fetch upstream`
2. Switch to `master` branch:

    `$ git checkout master`
3. Merge the code fetched from upstream:

    `$ git merge upstream/master`
4. Push the merged code to your fork:

    `$ git push`

## Documentation
* `wget2`
    1. Once you built the project head over to `docs/html/index.html`
    2. `wget2 --help`
    3. [wget2 GitLab wiki](https://gitlab.com/gnuwget/wget2/wikis/home)
* GnuTLS
    1. [GnuTLS Manual](https://www.gnutls.org/manual/gnutls.html)
* C
    1. [C99 Standard](http://www.open-std.org/jtc1/sc22/wg14/www/docs/n1256.pdf)
    2. [C99 Rationale](http://www.open-std.org/jtc1/sc22/wg14/www/docs/n897.pdf)
* `git`
    1. [Git Documentation](https://git-scm.com/doc)
    2. [Pro Git book](https://git-scm.com/book/en/v2)
* GitLab
    1. [GitLab Help](https://gitlab.com/help)
    2. [GitLab Docs](https://docs.gitlab.com/)
