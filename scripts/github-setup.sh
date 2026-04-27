#!/bin/bash
#
# DONET - GitHub Repository Setup
# This script helps you create a GitHub repository and push your code
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== DONET GitHub Repository Setup ===${NC}"
echo ""

# Check if git is installed
if ! command -v git &> /dev/null; then
    echo -e "${RED}ERROR: Git is not installed${NC}"
    echo "Install git first:"
    echo "  macOS: brew install git"
    echo "  Ubuntu/Debian: sudo apt install git"
    echo "  Kali: sudo apt install git"
    exit 1
fi

# Get repository name
REPO_NAME="network-analyzer"
CURRENT_DIR="$(pwd)"
PROJECT_NAME="$(basename "$CURRENT_DIR")"

echo -e "${YELLOW}This script will create a new GitHub repository and push your code.${NC}"
echo ""
echo "Project name: $PROJECT_NAME"
echo "Default GitHub repo name: $REPO_NAME"
echo ""

# Ask for GitHub username
read -p "Enter your GitHub username: " GITHUB_USER

if [ -z "$GITHUB_USER" ]; then
    echo -e "${RED}ERROR: GitHub username is required${NC}"
    exit 1
fi

# Ask if they want to use default repo name
read -p "Use repository name '$REPO_NAME'? (Y/n): " USE_DEFAULT
USE_DEFAULT=${USE_DEFAULT:-Y}

if [[ $USE_DEFAULT =~ ^[Yy]$ ]]; then
    REPO_NAME="$REPO_NAME"
else
    read -p "Enter repository name: " REPO_NAME
    if [ -z "$REPO_NAME" ]; then
        echo "Using default: $REPO_NAME"
        REPO_NAME="$REPO_NAME"
    fi
fi

# Ask for visibility
read -p "Make repository public or private? (public/private) [public]: " VISIBILITY
VISIBILITY=${VISIBILITY:-public}

if [[ $VISIBILITY == "private" ]]; then
    VISIBILITY_FLAG="--private"
else
    VISIBILITY_FLAG="--public"
fi

echo ""
echo -e "${GREEN}Configuration:${NC}"
echo "  GitHub User: $GITHUB_USER"
echo "  Repository: $REPO_NAME"
echo "  Visibility: $VISIBILITY"
echo "  Local path: $CURRENT_DIR"
echo ""

# Check if already logged in to GitHub CLI
if command -v gh &> /dev/null; then
    echo "GitHub CLI detected. Using it to create repo..."
    gh repo create "$GITHUB_USER/$REPO_NAME" $VISIBILITY_FLAG --source="$CURRENT_DIR" --remote=origin --push
    echo -e "${GREEN}✓ Repository created and pushed!${NC}"
    echo ""
    echo "Your repo: https://github.com/$GITHUB_USER/$REPO_NAME"
    exit 0
fi

# Manual method
echo -e "${YELLOW}GitHub CLI not installed. Using manual method.${NC}"
echo ""
echo "Step 1: Create a new repository on GitHub"
echo "  Go to: https://github.com/new"
echo "  Repository name: $REPO_NAME"
echo "  Visibility: $VISIBILITY"
echo "  DO NOT initialize with README, .gitignore, or license (we already have them)"
echo ""
read -p "Press Enter after you've created the repository on GitHub..."

# Add remote
echo ""
echo "Step 2: Adding remote..."
git remote add origin "https://github.com/$GITHUB_USER/$REPO_NAME.git"

# Set branch to main (modern standard)
git branch -M main

# Push to GitHub
echo "Step 3: Pushing to GitHub..."
git push -u origin main

if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✓ Successfully pushed to GitHub!${NC}"
    echo ""
    echo "Your repository: https://github.com/$GITHUB_USER/$REPO_NAME"
    echo ""
    echo "Now others can install with:"
    echo "  curl -sSL https://raw.githubusercontent.com/$GITHUB_USER/$REPO_NAME/main/install.sh | bash"
    echo ""
    echo "Or:"
    echo "  git clone https://github.com/$GITHUB_USER/$REPO_NAME.git"
    echo ""
else
    echo -e "${RED}✗ Push failed.${NC}"
    echo "Possible reasons:"
    echo "  1. You haven't created the repo on GitHub yet"
    echo "  2. Authentication failed (need personal access token)"
    echo ""
    echo "To fix authentication:"
    echo "  a) Create a Personal Access Token on GitHub:"
    echo "     https://github.com/settings/tokens (classic) or fine-grained token"
    echo "  b) When prompted for password, use the token instead"
    echo ""
    echo "Or configure SSH keys for passwordless push:"
    echo "  https://docs.github.com/en/authentication/connecting-to-github-with-ssh"
    exit 1
fi
