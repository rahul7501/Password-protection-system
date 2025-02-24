#include <iostream>
#include <conio.h>
#include <string>
#include <fstream>
#include <CkPrng.h>
#include "sha256.h"
#include "md5.h"
#include <vector>
#include "uint256_t.h"
using namespace std;

const int N = 60100; // Size of bitarray for BF1 at 0.625% FPR
const int M = 10000; // Size of bitarray for BF2

// Function prototypes
bool lookupBF1_8(string, bool*);
bool lookupBF1_10(string, bool*);
bool lookupBF1_12(string, bool*);
void insertBF1_8(bool*);
void insertBF1_10(bool*);
void insertBF1_12(bool*);
void insertBF1(bool*, bool*, bool*);
bool isLengthValid(string);
bool isPasswordAccepted(string, bool*, bool*, bool*);
bool isValidUID(string, vector<string>);
void writeToFile(string, string, vector<string>);
vector<bool> create_bitarray_element(vector<vector<bool>>);
void insertBF2(string, vector<vector<bool>>);
void updateBF2(string, vector<vector<bool>>);
bool lookupBF2(string, string);
vector<bool> hash_bigram(string);
void updateFile(string, string, vector<string>);
vector<vector<bool>> create_vectors_of_bigrams(string);
void account_registration(bool*, bool*, bool*, vector<string>&);
void signin();
void update_password(bool*, bool*, bool*, vector<string>);

// Modulus Function For Positive and Negative Numbers
int mod(long long int dividend, int divisor)
{
	long int m = dividend % divisor;
	return m + (m < 0 ? divisor : 0);
}

// Hash Function 1
int h1(string password)
{
	long long int hash = 0, mul = 1;
	for (int i = 0; i < password.size(); i++) {
		mul = (i % 4 == 0) ? 1 : mul * 256;
		hash += (int)password[i] * mul;
	}
	return mod(abs(hash), N);
}

// Hash Function 2
int h2(string password)
{
	long long int hash = 0;
	for (int i = 0; i < password.size(); i++)
	{
		hash += (int)password[i] * pow(7, i);
	}
	return mod(hash, N);
}

// Hash Function 3
int h3(string password)
{
	long long int hash = 0;
	for (int i = 0; i < password.size(); i++)
	{
		hash = hash * 53 + (int)password[i]; //23, 53, 97
	}
	return mod(hash, N);
}

// Hash Function 4
int h4(string password)
{
	long long int hash = 0;
	for (int i = 0; i < password.size(); i++)
	{
		hash += hash * 5 + (int)password[i] * pow(5, i);
	}
	return mod(hash, N);
}

// Hash Function 5
int h5(string password)
{
	long long int hash = 0;
	for (int i = 0; i < password.size(); i++)
	{
		hash += (int)password[i] * 5 - pow((int)password[i], 4);
	}
	return mod(abs(hash), N);
}

// Hash Function 6
int h6(string password)
{
	long int b = 401179;
	long int a = 3853;
	long long int hash = 0;
	int i = 0;
	for (i = 0; i < password.size(); i++)
	{
		hash = hash * a + (int)password[i];
		a = a * b;
	}
	return mod(hash, N);
}

// Hash Function 7
int h7(string password)
{
	long long int hash = 3607;
	for (int i = 0; i < password.size(); i++) {
		hash = ((hash << 5) + hash) + (int)password[i];
	}
	return mod(hash, N);
}

// Hash Function 8
int h8(string password)
{
	long long int hash = 0;
	for (int i = 0; i < password.size(); i++) {
		hash = (int)password[i] + (hash << 6) + (hash << 16) - hash;
	}
	return mod(hash, N);
}

// Hash Function 9
int h9(string password)
{
	long long int hash = 120461672;
	for (int i = 0; i < password.size(); i++)
	{
		hash ^= ((hash << 5) + (int)password[i] + (hash >> 2));
	}
	return mod(hash, N);
}

// Hash Function 10
int h10(string password)
{
	long int seed = 13131; /* 31 131 1313 13131 131313 etc.. */
	long long int hash = 0;
	for (int i = 0; i < password.size(); i++)
	{
		hash = (hash * seed) + (int)password[i];
	}
	return mod(hash, N);
}

// Hash Function 11
int h11(string password)
{
	long long int hash = 4277;
	for (int i = 0; i < password.size(); i++)
	{
		hash = ((hash << 5) + hash) + (int)password[i];
	}
	return mod(hash, N);
}

// Hash Function 12
int h12(string password)
{
	long long int hash = password.size();
	for (int i = 0; i < password.size(); i++)
	{
		hash = ((hash << 5) ^ (hash >> 27)) ^ (int)password[i];
	}
	return mod(hash, N);
}

// Hash Function 13
int h13(string password)
{
	long long int hash = 0xAAAAAAAA;
	for (int i = 0; i < password.size(); i++)
	{
		hash ^= ((i & 1) == 0) ? ((hash << 7) ^ (int)password[i] * (hash >> 3)) :
			(~((hash << 11) + ((int)password[i] ^ (hash >> 5))));
	}
	return mod(hash, N);
}

// Hash Function 14
int h14(string password)
{
	const unsigned int BitsInUnsignedInt = (unsigned int)(sizeof(unsigned int) * 8);
	const unsigned int ThreeQuarters = (unsigned int)((BitsInUnsignedInt * 3) / 4);
	const unsigned int OneEighth = (unsigned int)(BitsInUnsignedInt / 8);
	const unsigned int HighBits = (unsigned int)(0xFFFFFFFF) << (BitsInUnsignedInt - OneEighth);
	long long int hash = 0;
	int test = 0;
	for (int i = 0; i < password.size(); i++)
	{
		hash = (hash << OneEighth) + (int)password[i];

		if ((test = hash & HighBits) != 0)
		{
			hash = ((hash ^ (test >> ThreeQuarters)) & (~HighBits));
		}
	}
	return mod(hash, N);
}

// Hash Function 15
int h15(string password)
{
	long long int hash = 131313;
	for (int i = 0; i < password.size(); i++)
	{
		hash += pow((int)password[i], 3) - (int)password[i] * 7;
	}
	return mod(abs(hash), N);
}

// Function to convert a hex number to a hex string
uint256_t convert(string number) {
	int len = number.length();
	uint256_t base = 1;		// First base => 16^0 = 1
	uint256_t value = 0;

	for (int i = len - 1; i >= 0; i--) {
		if (number[i] >= '0' && number[i] <= '9') {			// If the character is b/w 0 and 9
			value += (number[i] - 48) * base;			// Multiplying the base with the hex representation of the character 
			base = base * 16;						// Increasing the base by the factor of 16
		}
		else if (number[i] >= 'A' && number[i] <= 'F') {	// If the character is b/w A and F
			value += (number[i] - 55) * base;
			base = base * 16;
		}
		else if (number[i] >= 'a' && number[i] <= 'f') {	// If the character is b/w a and f
			value += (number[i] - 87) * base;
			base = base * 16;
		}
	}
	return value;
}

int main()
{
	bool bitarrayBF1_8[N] = { false };				// Initializing the bloom filter 1 for 8 characters with size N and values as false/0
	bool bitarrayBF1_10[N] = { false };				// Initializing the bloom filter 1 for 10 characters with size N and values as false/0
	bool bitarrayBF1_12[N] = { false };				// Initializing the bloom filter 1 for 12 characters with size N and values as false/0
	insertBF1(bitarrayBF1_8, bitarrayBF1_10, bitarrayBF1_12);		// inserting the rockyou dictionary into the filters

	vector<string> UIDList;				// Declaring a vector to store the UIDs present in the file

	ifstream in("password_file.txt");	// Creating stream to read the file
	if (in) {
		string field;
		in.seekg(0, ios::end);
		int size = in.tellg();
		if (size != 0)
		{
			in.seekg(0, ios::beg);
			while (!in.eof()) {
				for (int i = 0; i < 3; i++) {		// 3 colums in the file (UID, salt, hash)
					if (i == 2)
						getline(in, field);
					else if (i == 1) {
						getline(in, field, ' ');
					}
					else {
						getline(in, field, ' ');	// Storing the 1st field (UID) into the vector
						UIDList.push_back(field);
					}
				}
			}
		}
	}
	in.close();

	while (true) {
		int choice;
		cout << endl;
		cout << "****************WELCOME****************" << endl;
		cout << "*                                     *" << endl;
		cout << "*    1 ==> Register an account        *" << endl;
		cout << "*    2 ==> Sign In                    *" << endl;
		cout << "*    3 ==> Update/Change password     *" << endl;
		cout << "*    4 ==> Exit                       *" << endl;
		cout << "*                                     *" << endl;
		cout << "***************************************" << endl << endl;
		cout << "Enter your choice: ";
		cin >> choice;
		switch (choice) {
		case 1:account_registration(bitarrayBF1_8, bitarrayBF1_10, bitarrayBF1_12, UIDList); break;
		case 2:signin(); break;
		case 3:update_password(bitarrayBF1_8, bitarrayBF1_10, bitarrayBF1_12, UIDList); break;
		case 4:exit(0);
		default:cout << "\nWrong choice! Try Again :(" << endl; break;
		}
	}
	return 0;
}

// Function to insert into bloom filter 1 of 8 characters from rockyou-8
void insertBF1_8(bool* bitarrayBF1_8) {
	ifstream in("rockyou-8.txt");				// Creating stream to read the file
	if (!in) {
		cout << "File Not Found\n";
		exit(1);
	}

	string common_password;

	// Loop to read each word from file and hash using th 15 hash functions and placing in those positions true
	while (in >> common_password) {
		bitarrayBF1_8[h1(common_password)] = true;
		bitarrayBF1_8[h2(common_password)] = true;
		bitarrayBF1_8[h3(common_password)] = true;
		bitarrayBF1_8[h4(common_password)] = true;
		bitarrayBF1_8[h5(common_password)] = true;
		bitarrayBF1_8[h6(common_password)] = true;
		bitarrayBF1_8[h7(common_password)] = true;
		bitarrayBF1_8[h8(common_password)] = true;
		bitarrayBF1_8[h9(common_password)] = true;
		bitarrayBF1_8[h10(common_password)] = true;
		bitarrayBF1_8[h11(common_password)] = true;
		bitarrayBF1_8[h12(common_password)] = true;
		bitarrayBF1_8[h13(common_password)] = true;
		bitarrayBF1_8[h14(common_password)] = true;
		bitarrayBF1_8[h15(common_password)] = true;
	}
	in.close();
}

// Function to insert into bloom filter 1 of 8 characters from rockyou-10
void insertBF1_10(bool* bitarrayBF1_10) {
	ifstream in("rockyou-10.txt");				// Creating stream to read the file
	if (!in) {
		cout << "File Not Found\n";
		exit(1);
	}

	string common_password;

	// Loop to read each word from file and hash using th 15 hash functions and placing in those positions true
	while (in >> common_password) {
		bitarrayBF1_10[h1(common_password)] = true;
		bitarrayBF1_10[h2(common_password)] = true;
		bitarrayBF1_10[h3(common_password)] = true;
		bitarrayBF1_10[h4(common_password)] = true;
		bitarrayBF1_10[h5(common_password)] = true;
		bitarrayBF1_10[h6(common_password)] = true;
		bitarrayBF1_10[h7(common_password)] = true;
		bitarrayBF1_10[h8(common_password)] = true;
		bitarrayBF1_10[h9(common_password)] = true;
		bitarrayBF1_10[h10(common_password)] = true;
		bitarrayBF1_10[h11(common_password)] = true;
		bitarrayBF1_10[h12(common_password)] = true;
		bitarrayBF1_10[h13(common_password)] = true;
		bitarrayBF1_10[h14(common_password)] = true;
		bitarrayBF1_10[h15(common_password)] = true;
	}
	in.close();
}

// Function to insert into bloom filter 1 of 8 characters from rockyou-10
void insertBF1_12(bool* bitarrayBF1_12) {
	ifstream in("rockyou-12.txt");				// Creating stream to read the file
	if (!in) {
		cout << "File Not Found\n";
		exit(1);
	}

	string common_password;

	// Loop to read each word from file and hash using th 15 hash functions and placing in those positions true
	while (in >> common_password) {
		bitarrayBF1_12[h1(common_password)] = true;
		bitarrayBF1_12[h2(common_password)] = true;
		bitarrayBF1_12[h3(common_password)] = true;
		bitarrayBF1_12[h4(common_password)] = true;
		bitarrayBF1_12[h5(common_password)] = true;
		bitarrayBF1_12[h6(common_password)] = true;
		bitarrayBF1_12[h7(common_password)] = true;
		bitarrayBF1_12[h8(common_password)] = true;
		bitarrayBF1_12[h9(common_password)] = true;
		bitarrayBF1_12[h10(common_password)] = true;
		bitarrayBF1_12[h11(common_password)] = true;
		bitarrayBF1_12[h12(common_password)] = true;
		bitarrayBF1_12[h13(common_password)] = true;
		bitarrayBF1_12[h14(common_password)] = true;
		bitarrayBF1_12[h15(common_password)] = true;
	}
	in.close();
}

// Function to insert into all the bloom filter 1s
void insertBF1(bool* bitarrayBF1_8, bool* bitarrayBF1_10, bool* bitarrayBF1_12) {
	insertBF1_8(bitarrayBF1_8);		// Calling the function to insert into bloom filter 1 for 8 characters
	insertBF1_10(bitarrayBF1_10);   // Calling the function to insert into bloom filter 1 for 10 characters
	insertBF1_12(bitarrayBF1_12);   // Calling the function to insert into bloom filter 1 for 12 characters
}

// Function to lookup if a password is present in the bloom filter 1 of 8 charcaters
bool lookupBF1_8(string password, bool* bitarrayBF1_8) {
	int h1val = h1(password), h2val = h2(password), h3val = h3(password), h4val = h4(password), h5val = h5(password);
	int h6val = h6(password), h7val = h7(password), h8val = h8(password), h9val = h9(password), h10val = h10(password);
	int h11val = h11(password), h12val = h12(password), h13val = h13(password), h14val = h14(password), h15val = h15(password);

	// Only if at all positions it is true means the password is present in the bloom filter
	if (bitarrayBF1_8[h1val] && bitarrayBF1_8[h2val] && bitarrayBF1_8[h3val] && bitarrayBF1_8[h4val] &&
		bitarrayBF1_8[h5val] && bitarrayBF1_8[h6val] && bitarrayBF1_8[h7val] && bitarrayBF1_8[h8val] &&
		bitarrayBF1_8[h9val] && bitarrayBF1_8[h10val] && bitarrayBF1_8[h11val] && bitarrayBF1_8[h12val] &&
		bitarrayBF1_8[h13val] && bitarrayBF1_8[h14val] && bitarrayBF1_8[h15val]) {
		return true;
	}
	return false;
}

// Function to lookup if a password is present in the bloom filter 1 of 10 charcaters
bool lookupBF1_10(string password, bool* bitarrayBF1_10) {
	int h1val = h1(password), h2val = h2(password), h3val = h3(password), h4val = h4(password), h5val = h5(password);
	int h6val = h6(password), h7val = h7(password), h8val = h8(password), h9val = h9(password), h10val = h10(password);
	int h11val = h11(password), h12val = h12(password), h13val = h13(password), h14val = h14(password), h15val = h15(password);

	// Only if at all positions it is true means the password is present in the bloom filter
	if (bitarrayBF1_10[h1val] && bitarrayBF1_10[h2val] && bitarrayBF1_10[h3val] && bitarrayBF1_10[h4val] &&
		bitarrayBF1_10[h5val] && bitarrayBF1_10[h6val] && bitarrayBF1_10[h7val] && bitarrayBF1_10[h8val] &&
		bitarrayBF1_10[h9val] && bitarrayBF1_10[h10val] && bitarrayBF1_10[h11val] && bitarrayBF1_10[h12val] &&
		bitarrayBF1_10[h13val] && bitarrayBF1_10[h14val] && bitarrayBF1_10[h15val]) {
		return true;
	}
	return false;
}

// Function to lookup if a password is present in the bloom filter 1 of 12 charcaters
bool lookupBF1_12(string password, bool* bitarrayBF1_12) {
	int h1val = h1(password), h2val = h2(password), h3val = h3(password), h4val = h4(password), h5val = h5(password);
	int h6val = h6(password), h7val = h7(password), h8val = h8(password), h9val = h9(password), h10val = h10(password);
	int h11val = h11(password), h12val = h12(password), h13val = h13(password), h14val = h14(password), h15val = h15(password);

	// Only if at all positions it is true means the password is present in the bloom filter
	if (bitarrayBF1_12[h1val] && bitarrayBF1_12[h2val] && bitarrayBF1_12[h3val] && bitarrayBF1_12[h4val] &&
		bitarrayBF1_12[h5val] && bitarrayBF1_12[h6val] && bitarrayBF1_12[h7val] && bitarrayBF1_12[h8val] &&
		bitarrayBF1_12[h9val] && bitarrayBF1_12[h10val] && bitarrayBF1_12[h11val] && bitarrayBF1_12[h12val] &&
		bitarrayBF1_12[h13val] && bitarrayBF1_12[h14val] && bitarrayBF1_12[h15val]) {
		return true;
	}
	return false;
}

// Function to check if the length of the password is 8/10/12
bool isLengthValid(string password) {
	int password_length = password.length();

	if (password_length != 8 && password_length != 10 && password_length != 12)
		return false;

	return true;
}

// Function to check if the password is accepted after looking it up in bloom filters
bool isPasswordAccepted(string password, bool* bitarrayBF1_8, bool* bitarrayBF1_10, bool* bitarrayBF1_12) {
	int password_length = password.length();
	bool presence_in_BF1;

	switch (password_length) {
	case 8:presence_in_BF1 = lookupBF1_8(password, bitarrayBF1_8); break;
	case 10:presence_in_BF1 = lookupBF1_10(password, bitarrayBF1_10); break;
	case 12:presence_in_BF1 = lookupBF1_12(password, bitarrayBF1_12); break;
	}

	if (presence_in_BF1) // If a presence is found in any of the bloom filters, then the password is common and is not accepted
		return false;

	return true;
}

// Function to check if the UID exists already
bool isValidUID(string UID, vector<string> UIDList) {
	for (int i = 0; i < UIDList.size(); i++) {
		if (UID == UIDList[i])		// If the UID exists means the user cannot have this UID
			return false;
	}
	return true;
}

// Function to write to the password file once the password has been accepted after registering the account
void writeToFile(string UID, string password, vector<string> UIDList) {
	fstream out;								// Creating stream to write to the file in append mode
	out.open("password_file.txt", ios::app);
	if (!out) {
		cout << "File Not Found\n";
		exit(1);
	}

	CkPrng prng;		// Declaring an instance from Chilkat library to generate pseudorandom number
	SHA256 sha256;		// Declaring an instance of SHA256

	string salt = prng.genRandom(32, "hex");	// Generating a salt of 32 bytes in hex
	string salt_pass = salt + password;			// Appending the password to the salt
	string hashPassword = sha256(salt_pass);	// Hashing the salt + password using sha256

	if (UIDList.size() == 1) {				// If the file is empty, the number of UIDs that exist is 1
		out << UID << ' ' << salt << ' ' << hashPassword;		// Write to file w/o endl
	}
	else {
		out << endl << UID << ' ' << salt << ' ' << hashPassword;	// Write to file with endl
	}
	out.close();
}

// Function to update the file after the password has been updated
void updateFile(string password, string UID, vector<string> UIDList) {
	ifstream in("password_file.txt");		// Creating a stream to read the password file
	ofstream out("temp.txt");				// Creating a stream to write to a temporary file
	if (!in) {
		cout << "File Not Found\n";
		exit(1);
	}

	string UID_file, salt_file, hash_file;
	CkPrng prng;
	SHA256 sha256;

	while (!in.eof()) {
		in >> UID_file >> salt_file >> hash_file;
		if (UID == UID_file && UID_file == UIDList.at(0)) {	// If UID of the user is same as UID in he file and this UID is the first in the file
			string salt = prng.genRandom(32, "hex");
			string salt_pass = salt + password;
			string hashPassword = sha256(salt_pass);
			out << UID_file << ' ' << salt << ' ' << hashPassword;	// Write to file w/o endl
			continue;
		}
		else if (UID == UID_file) { // If UID of the user is same as UID in he file and this UID is not the first in the file
			string salt = prng.genRandom(32, "hex");
			string salt_pass = salt + password;
			string hashPassword = sha256(salt_pass);
			out << endl << UID_file << ' ' << salt << ' ' << hashPassword;	// Write to file with endl
			continue;
		}
		else if (UID != UID_file && UID_file == UIDList.at(0)) {
			out << UID_file << ' ' << salt_file << ' ' << hash_file;	// Write to file w/o endl
			continue;
		}
		out << endl << UID_file << ' ' << salt_file << ' ' << hash_file;	// Otherwise always write to the file with endl
	}
	in.close();
	out.close();

	remove("password_file.txt");	// Remove the password file
	rename("temp.txt", "password_file.txt");	// Rename the temp file as password file
}

// Function that does the bitwise or for all the bigram vectors and returns the final bloom filter of the password
vector<bool> create_bitarray_element(vector<vector<bool>> bitarray_element) {
	vector<bool> bitarray_password(M, false);	// Initializing the vector 

	for (int i = 0; i < M; i++)
	{
		for (int j = 0; j < bitarray_element.size(); j++)
		{
			bitarray_password[i] = bitarray_element[j][i] | bitarray_password[i];		// Accessing each column by column
			/*if (bitarray_element[j][i]) {
				bitarray_password[i] = bitarray_element[j][i];
				break;
			}*/
		}
	}
	return bitarray_password;
}

// Function that inserts the accepted password after registration into a bloom filter 2 for each user
void insertBF2(string UID, vector<vector<bool>> bitarray_element)
{
	vector<bool> bitarray_password = create_bitarray_element(bitarray_element);	// Obtains the final bloom filter of password after computing the bitwise or for all the bigram vectors

	ofstream out(UID + "bloomfilter2.txt");		// Creating a stream to write to the user's bloom filter 2
	for (int i = 0; i < bitarray_password.size(); i++)
	{
		out << bitarray_password[i] << " ";
	}
	out.close();
}

// Function that updates the existing bloom filter 2 of the user with the updated password
void updateBF2(string UID, vector<vector<bool>> bitarray_element)
{
	vector<bool> bitarray_password = create_bitarray_element(bitarray_element);	// Obtains the final bloom filter of password after computing the bitwise or for all the bigram vectors

	ifstream in(UID + "bloomfilter2.txt");	// Creating a stream to read the user's existing bloom filter 2
	vector<bool> bitarray_user_BF2;		// Declaring a vector to store the previous bloom filter 2 of the user
	bool value;

	while (in >> value) {
		bitarray_user_BF2.push_back(value);
	}
	in.close();

	// Loop to store the updated password into the existing bloom filter 2 of the user
	for (int i = 0; i < M; i++) {
		if (bitarray_user_BF2[i])	// If the bloom filter 2 value is 1 go to the next iteration
			continue;
		bitarray_user_BF2[i] = bitarray_password[i];
	}

	ofstream out(UID + "bloomfilter2.txt");		// Creating a stream to write the user's new bloom filter 2
	for (int i = 0; i < M; i++) {
		out << bitarray_user_BF2[i] << " ";
	}
	out.close();
}

// Function that checks for similarity of the new password entered by the user with the user's bloom filter 2
bool lookupBF2(string password, string UID) {

	vector<vector<bool>> bitarray_element = create_vectors_of_bigrams(password); // Obtains the vector of vectors containing the hashed bigram vectors
	vector<bool> bitarray_password = create_bitarray_element(bitarray_element);	// Obtains the final bloom filter of new password after computing the bitwise or for all the bigram vectors

	double count_common_true = 0;				// gamma of bitarray_password, bitarray_user_BF2
	double count_bitarray_password_true = 0;	// k of bitarray_password
	double count_bitarray_user_BF2_true = 0;	// k of bitarray_user_BF2

	ifstream in(UID + "bloomfilter2.txt");	// Creating stream to read the existing bloom filter 2 of the user
	vector<bool> bitarray_user_BF2;		// Declaring a vector to store the previous bloom filter 2 of the user
	bool value;
	while (in >> value) {
		bitarray_user_BF2.push_back(value);
	}
	in.close();

	// Loop to find - gamma of bitarray_password, bitarray_user_BF2; k of bitarray_password; k of bitarray_user_BF2
	for (int i = 0; i < M; i++) {
		if (bitarray_password[i] == bitarray_user_BF2[i] && bitarray_password[i] == true && bitarray_user_BF2[i] == true)	// If the bloom filter 2 of the user and the vector of the new password have at the same position true
			count_common_true++;

		if (bitarray_password[i])	// If the vector of the new password has true in the position
			count_bitarray_password_true++;

		if (bitarray_user_BF2[i])	// If the bloom filter 2 of the user has true in the position
			count_bitarray_user_BF2_true++;
	}

	double jaccard_coefficient = count_common_true / (count_bitarray_password_true + count_bitarray_user_BF2_true - count_common_true);	// Finding jaccard coefficient

	if (jaccard_coefficient > 0.2) {	// If the jaccard coefficient is greater than 0.2 means the new password is similar to an already accepted password
		return false;
	}
	updateBF2(UID, bitarray_element);	// Calling the updateBF2 function if the new password isn't similar to add this new password into the BF2 of the user
	return true;
}

// Function that hashes each bigram 15 times using MD5 and SHA256
vector<bool> hash_bigram(string bigram)
{
	vector<bool> bitarray_bigram(M, false);

	for (int i = 0; i < 15; i++) {
		MD5 md5;												// Declaring an instance of MD5
		SHA256 sha256;											// Declaring an instance of SHA256
		string hashmd5 = md5(bigram);							// MD5 hash of bigram in string format
		uint256_t hash_md5 = convert(hashmd5);					// Converts the string format of MD5 hash into hex number
		string hashsha256 = sha256(bigram);						// SHA256 hash of bigram in string format
		uint256_t hash_sha256 = convert(hashsha256);			// Converts the string format of SHA256 hash into hex number
		uint32_t hashval = (hash_md5 + (i * hash_sha256)) % M;	// Calculating the final hash value
		bitarray_bigram[hashval] = true;
	}

	return bitarray_bigram;
}

// Function that returns the vector of vectors containing the hashed bigram vectors
vector<vector<bool>> create_vectors_of_bigrams(string password) {
	password.insert(0, "_");
	password.append("_");
	vector<vector<bool>> bitarray_element;		// Declaring the vector that stores all the hashed bigram vectors together
	for (int i = 0; i < password.length(); i++)
	{
		if (i == password.length() - 1)
			break;
		string bigram = "";
		bigram += password[i];
		bigram += password[i + 1];
		vector<bool> bitarray_bigram = hash_bigram(bigram);		// Creating the bigram vector for the password after hashing
		bitarray_element.push_back(bitarray_bigram);		// Adding it to the vector that stores all the bigram vectors together
	}
	return bitarray_element;
}

// Function that registers an account for the user
void account_registration(bool* bitarrayBF1_8, bool* bitarrayBF1_10, bool* bitarrayBF1_12, vector<string>& UIDList) {
	string name, password, UID;
	char ch, option;
	bool validity, validLength, validUID;

	cout << "\nEnter your name: ";
	cin >> name;

	do {
		password = "";
		cout << "Enter your password: ";
		cin >> password;

		validLength = isLengthValid(password);		// Checks if the length is 8/10/12

		if (validLength) {

			validity = isPasswordAccepted(password, bitarrayBF1_8, bitarrayBF1_10, bitarrayBF1_12);		// Checks if the password belongs to any of the bloom filter 1s

			if (validity) {
				cout << "Password Accepted :)" << endl;
				cout << "Enter your username: ";
				cin >> UID;
				bool validUID = isValidUID(UID, UIDList);	// Checks if UID already exists
				if (validUID) {
					UIDList.push_back(UID);					// Adds the accepted UID into the list of UIDs
					writeToFile(UID, password, UIDList);	// Adds this new account to the password file
					vector<vector<bool>> bitarray_element = create_vectors_of_bigrams(password); // Obtains the vector of vectors containing the hashed bigram vectors
					insertBF2(UID, bitarray_element);	// Inserts this password to the user's bloom filter 2
					cout << "\nAccount Registered Successfully" << endl;
					break;
				}
				else {
					cout << "Sorry username taken, enter another username: ";
				}
			}
			else {
				cout << "Password entered is common" << endl << endl;
			}
		}
		else {
			cout << "Please enter a password of length 8 or 10 or 12 characters only" << endl << endl;
		}

		cout << "Do you wish to retry? (y/n): ";
		cin >> option;
		cout << endl;

	} while (option == 'y' || option == 'Y');
}

// Function that allows a user to signin
void signin() {
	string UID, password, UID_file, salt_file, hash_file;
	ifstream in("password_file.txt");
	if (!in) {
		cout << "File Not Found\n";
		exit(1);
	}
	bool flag = false;
	char option;
	do {
		cout << "\nEnter your UID: ";
		cin >> UID;

		// Checking if the UID is present in the password file
		in.seekg(0, ios::beg);
		while (!in.eof()) {
			in >> UID_file >> salt_file >> hash_file;
			if (UID == UID_file) {
				flag = true;
				break;
			}
		}

		if (flag) {									// If the UID exists in the password file
			cout << "Enter your password: ";
			cin >> password;
			SHA256 sha256;
			string salt_pass = salt_file + password;		// Appending the password entered by the user, to the salt obtained from the password file
			string hash = sha256(salt_pass);		// Computing the hash of salt from file + password by user
			if (hash == hash_file) {		// Checks if the hash values are the same
				cout << "\nYou have signed in successfully" << endl;
				break;
			}
			else {
				cout << "Wrong password" << endl << endl;
			}
		}
		else {
			cout << "UID does not exist!" << endl << endl;
		}

		cout << "Do you wish to retry? (y/n): ";
		cin >> option;

	} while (option == 'y' || option == 'Y');
	in.close();
}

// Function that allows a user to update their old password to a new password
void update_password(bool* bitarrayBF1_8, bool* bitarrayBF1_10, bool* bitarrayBF1_12, vector<string> UIDList) {
	string UID, oldpassword, newpassword, UID_file, salt_file, hash_file;

	bool validity1, validity2, validLength, flag = false;
	char option;
	do {
		cout << "\nEnter your UID: ";
		cin >> UID;

		// Checking if the UID is present in the password file
		ifstream in("password_file.txt");
		in.seekg(0, ios::beg);
		while (!in.eof()) {
			in >> UID_file >> salt_file >> hash_file;
			if (UID == UID_file) {
				flag = true;
				break;
			}
		}
		in.close();

		if (flag) {										// If the UID exists in the password file
			cout << "Enter your old password: ";
			cin >> oldpassword;
			SHA256 sha256;
			string salt_pass = salt_file + oldpassword;
			string hash = sha256(salt_pass);
			if (hash == hash_file) {   // If the hash values are same, means the user is authentic
				newpassword = "";
				cout << "Enter your new password: ";
				cin >> newpassword;

				validLength = isLengthValid(newpassword);		// Checks if the length is 8/10/12

				if (validLength) {
					validity1 = isPasswordAccepted(newpassword, bitarrayBF1_8, bitarrayBF1_10, bitarrayBF1_12);		// Checks if the password belongs to any of the bloom filter 1s

					if (validity1) {
						validity2 = lookupBF2(newpassword, UID);	// Checks if the new password is similar to the old password

						if (validity2) {
							updateFile(newpassword, UID, UIDList);	// Updates the password file with this new accepted password
							cout << "\nPassword Changed Successfully" << endl;
							break;
						}
						else {
							cout << "Cannot accept this password!" << endl << endl;
						}
					}
					else {
						cout << "Password entered is common" << endl << endl;
					}
				}
				else {
					cout << "Please enter a password of length 8 or 10 or 12 characters only" << endl << endl;
				}
			}
			else {
				cout << "Wrong password" << endl << endl;
			}
		}
		else {
			cout << "UID does not exist!" << endl << endl;
		}

		cout << "Do you wish to retry? (y/n): ";
		cin >> option;

	} while (option == 'y' || option == 'Y');
}