REPO="https://github.com/TwigaDEVs/KaziNear.git" 

# Branch name
BRANCH="main"


# Clone repo
git clone  $REPO 
cd  KaziNear/

if [ -d "frontend" ]; then

  # Change directory
  cd frontend
  
  # Install npm packages
  npm install

  # Run dev server
  npm run dev
  
else
  echo "web-frontend folder not found"
  exit 1
fi
