#!/bin/bash
# Script to push the Remote Patient repository to GitHub

echo "============================================="
echo "    Remote Patient GitHub Push Script"
echo "============================================="

# Check if Git is installed
if ! command -v git &> /dev/null; then
    echo "Error: Git is not installed. Please install Git first."
    exit 1
fi

# Navigate to project root directory
cd "$(dirname "$0")"
echo "Working directory: $(pwd)"

# Check if .git directory exists
if [ -d ".git" ]; then
    echo "Git repository already initialized."
else
    echo "Initializing Git repository..."
    git init
    if [ $? -ne 0 ]; then
        echo "Error: Failed to initialize Git repository."
        exit 1
    fi
fi

# Configure Git if needed
if [ -z "$(git config --get user.name)" ]; then
    echo "Enter your Git username:"
    read git_username
    git config user.name "$git_username"
fi

if [ -z "$(git config --get user.email)" ]; then
    echo "Enter your Git email:"
    read git_email
    git config user.email "$git_email"
fi

# Stage files
echo "Adding files to Git..."
git add .
if [ $? -ne 0 ]; then
    echo "Error: Failed to add files to Git."
    exit 1
fi

# Commit files
echo "Committing files..."
git commit -m "Initial commit: Remote Patient Monitoring System"
if [ $? -ne 0 ]; then
    echo "Error: Failed to commit files."
    exit 1
fi

# Check if remote exists
if git remote | grep -q "^origin$"; then
    echo "Remote 'origin' already exists."
else
    echo "Enter GitHub repository URL (https://github.com/NOVUMSOLVO/Remote-Patient.git):"
    read repo_url
    if [ -z "$repo_url" ]; then
        repo_url="https://github.com/NOVUMSOLVO/Remote-Patient.git"
    fi
    echo "Adding remote 'origin'..."
    git remote add origin "$repo_url"
    if [ $? -ne 0 ]; then
        echo "Error: Failed to add remote repository."
        exit 1
    fi
fi

# Push to GitHub
echo "Pushing to GitHub..."
git push -u origin main
if [ $? -ne 0 ]; then
    echo "Initial push failed, trying with 'master' branch instead..."
    git push -u origin master
    if [ $? -ne 0 ]; then
        echo "Error: Failed to push to GitHub. Check your credentials and repository access."
        echo "You might need to create a Personal Access Token on GitHub."
        exit 1
    fi
fi

echo "============================================="
echo "  Repository successfully pushed to GitHub!"
echo "============================================="
echo "Next steps:"
echo "1. Visit https://github.com/NOVUMSOLVO/Remote-Patient"
echo "2. Update the repository description"
echo "3. Configure branch protection rules"
echo "4. Set appropriate repository topics"
echo "============================================="