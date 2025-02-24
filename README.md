# Password-protection-system
A console application used for authenticating users through credentials verification. The program is designed to reject weak and commonly used passwords using the concept of bloom filters.The password files of all users are protected using salting and hashing of passwords.

🚀 Features
✅ Add new user
✅ Sign in to an account
✅ Update password
✅ Reject common passwords
✅ Reject similar passwords

📂 Project Structure
/
  ├── BloomFilterAssignment.cpp
  ├── rockyou-8.txt
  ├── rockyou-10.txt
  ├── rockyou-12.txt
  ├── password_file.txt (contains usernames, salt, hashed password)

  🛠️ Installation and Running Locally
  git clone https://github.com/rahul7501/password-protection-system.git
  #####TODO
  

  ⚡ Tech Stack
  C++
  SHA256 hash function
  MD5 hash function
  Chilkat pseudorandom number generator
