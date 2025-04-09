# Branch Protection Rules

This project uses GitHub Branch Protection Rules to ensure code quality and prevent breaking changes from being merged to the main branch.

## Setting up Branch Protection

1. Navigate to your GitHub repository
2. Go to `Settings` > `Branches`
3. Under `Branch protection rules`, click `Add rule`
4. Configure the following settings:

### Basic Settings

- Branch name pattern: `main`
- Check "Require a pull request before merging"
- Check "Require approvals" and set it to at least 1

### Status Checks

- Check "Require status checks to pass before merging"
- Check "Require branches to be up to date before merging"
- In the status checks search box, select all the CI checks:
  - `Static Analysis`
  - `Build`
  - `Test`

### Additional Settings (Recommended)

- Check "Include administrators" to ensure everyone follows the same rules
- Check "Restrict who can push to matching branches" and add appropriate teams/users
- Check "Allow force pushes" and select "Specify who can force push" for administrators only

## Effect of these Rules

With these rules in place:

1. Direct pushes to the `main` branch are prevented
2. All changes must go through pull requests
3. Pull requests require at least one approval
4. All CI checks must pass before merging
5. Branches must be up-to-date with the base branch before merging

This ensures that:
- Code is reviewed
- Tests pass
- Static analysis is successful
- The codebase maintains high quality standards 