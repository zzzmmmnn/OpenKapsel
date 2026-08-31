# Repository Workflow

## Branches and commits

- Do not make ongoing development commits directly on `main`.
- Create a dedicated local branch for each coherent batch of work.
- Intermediate implementation and fix commits are allowed on the working branch.
- Keep changes on the working branch until the user explicitly approves integrating them into `main`.
- Do not push a branch or create a GitHub pull request unless the user explicitly requests it.

## Verification

- Review the final diff and run the relevant tests before integration.
- Do not treat a branch as ready merely because its intermediate commits succeed individually.

## Integrating into main

- Use a local squash merge so each completed branch becomes one well-described commit on `main`.
- Do not use a merge commit or rebase merge for this workflow.
- Before integration, update `main` with a fast-forward-only pull when a remote is available.
- The intended sequence is:

  ```bash
  git switch main
  git pull --ff-only
  git merge --squash <working-branch>
  git commit -m "<complete summary of the integrated change>"
  ```

- Inspect and test the squashed result before pushing `main`.
- Delete the working branch only after the squashed commit has been verified, and only when the user has approved the cleanup.
