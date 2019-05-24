/*******************************************************************************
 * Troy Squillaci
 *
 * This program is a cipher that encrypts and decrypts data using the lejo
 * algorithm.  
 *
 * This program accepts text files from the standard input. Text files must 
 * conform to the following format to be considered valid by the program:
 *
 * A line must consist of the following tokens in order:
 * 
 * ACTION: Indicates if encryption of decryption should be perfromed.
 *         Legal values are 'e' for encryption and 'd' for decryption.
 * LCG_M:  Indicates the m value used for the linear congruential generator.
 *         Legal values are numbers that an unsigned long long int can contain.
 * LCG_C   Indicates the c value used for the linear congruential generator.
 *         Legal values are numbers that an unsigned long long int can contain.
 * DATA:   Indicates the data to be manipulated.
 *         Legal data is characters in the printable ASCII range.
 *
 * A example: e38875,1234,This program is awesome!
 *
 * In this example, the program is instructed to encrypt the string of 
 * characters "This program is awesome!" using m = 38875 abd c = 1234 for the
 * linear congruential generator.
 *
 * The program will print its output to the standard output stream.
 ******************************************************************************/
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#define MAP_LENGTH 28

//Toggle specific debugging options.
#define DEBUG_GENERAL 0
#define DEBUG_ERROR 0
#define DEBUG_READ_NUMBER 0
#define DEBUG_FACTORIZATION 0
#define DEBUG_LCG 0
#define DEBUG_BUILDING_MAP 0
#define DEBUG_BUILT_MAP 0
#define DEBUG_ENCRYPT 0
#define DEBUG_DECRYPT 0

//Indicates encryption or decryption.
static int cipher_mode;

//Indicates execution status throughout the program.
int status;
const int CLEAR = 0;
const int OK = 1;
const int END_OF_LINE = 2;
const int END_OF_FILE = 4;
const int ERROR = 8;

//For the linear congruential generator.
static int max = 0;

static unsigned long long lcg_c;
static unsigned long long lcg_m;
static unsigned long long lcg_a;
static unsigned long long lcg_x;

//For mapping.
static unsigned int builtMap[MAP_LENGTH];
static int assigned[MAP_LENGTH];
static int assigned_index[MAP_LENGTH];

//For prime factorization.
int factors[100] = {0};

//Function Prototypes
unsigned long long readNumber(char delimiter);
void calculatePrimeFactors(unsigned long long number);
void skipToEndOfLine(void);
int readDataBlock(char * data);
int readCipherMode(void);
int buildLCG(void);
void buildMap(void);
int isBitSet(char c, int n);
void setBit(char * c, int n);
int encryptText(char * data);
int decryptText(char * data);



/******************************************************************************/
/* readNumber(char delimiter)                                                 */
/*   Reads characters from the standard input stream until either             */
/*   the character read equals the delimiter or until an error.               */
/*                                                                            */
/*   An error occurs if:                                                      */
/*     1) A character is read that is not a digit (0-9) and not the delimiter.*/
/*     2) More than 20 digits are read                                        */
/*                                                                            */
/*   Returns                                                                  */
/*    If no error, returns an unsigned long long defined by the digits read.  */
/*    If an error, returns 0.                                                 */
/******************************************************************************/
unsigned long long readNumber(char delimiter)
{
  char active_char;
  char digits[21];
  int i = 0;
  int in_number = 0;
  
  memset(digits, 0, strlen(digits));
  
  * (digits + strlen(digits)) = '\0';
  
  while ((active_char = getchar()) != delimiter)
  {
    if (i == 20) return 0;
    if (isdigit(active_char))
    {
      if (active_char == '0' && !in_number) continue;
      if (active_char != '0' || in_number)
      {
        in_number = 1;
        * (digits + i++) = active_char;
      }
    }
    else return 0;
  }
  
  if (DEBUG_READ_NUMBER)
  {
    printf("digits is: %s\n", digits);
    printf("strtoull returned: %llu\n", strtoull(digits, NULL, 0));
  }
  
  return strtoull(digits, NULL, 0);
}



/******************************************************************************/
/* calculatePrimeFactors(unsigned long number)                                */
/*   Performs prime factorization on a number.                                */
/*                                                                            */
/* Parameters:                                                                */
/*   unsigned long number: The number to perform prime factorization on       */
/******************************************************************************/
void calculatePrimeFactors(unsigned long long number)
{
  int i;
  
  for (i = 0; i < 100; i++)
  {
    factors[i] = 0;
  }
  
  //If number is 1 or smaller return no prime factors
  if(number < 2)
  {
    factors[0] = 0;
    return;
  }
  
  i = 0;
  int divisor = 2;
  
  while(number > divisor)
  {
    //If prime number is found, add it to the prime numbers
    if(number % divisor == 0)
    {
      factors[i++] = divisor;
      number /= divisor;
    }
    //Else increment d for next pass
    else
    {
      if(divisor == 2) divisor = 3;
      else divisor += 2;
    }
  }
  
  factors[i++] = divisor;
  
  if (DEBUG_FACTORIZATION)
  {
    printf("The Prime Factors:\n");
    for (i = 0; i < 100; i++)
    {
      printf("%d\n", factors[i]);
    }
    printf("-----------------------------------------------------------\n");
  }
}



/******************************************************************************/
/* skipToEndOfLine(void)                                                      */
/* Helper function that reads characters from the                             */
/* standard input stream (stdin) until '\n' or EOF.                           */
/*                                                                            */
/* None of the characters read are saved.                                     */
/*                                                                            */
/* If '\n' is read, sets the END_OF_LINE flag of global field status.         */
/* If EOF is read, sets the END_OF_FILE flag of global field status.          */
/******************************************************************************/
void skipToEndOfLine(void)
{
  char active_char;
  int state = 1;
  
  while (state)
  {
    active_char = getchar();
    
    if (active_char == '\n')
    {
      status = END_OF_LINE;
      state = 0;
    }
    else if (active_char == EOF)
    {
      status = END_OF_FILE;
      state = 0;
    }
  }
}



/******************************************************************************/
/* readDataBlock(char * data)                                                 */
/*   Reads one block of data from the standard input stream.                  */
/*   Reading stops when a full block is read or when '\n' is read.            */
/*   An error is triggered if any byte code (other than '\n') is read         */
/*   that is not a printable ASCII character: [32, 126].                      */
/*                                                                            */
/* Parameters:                                                                */
/*   * data: A null-terminated array of size 5 into which the data is read.   */
/*     All elements of data are initialized to '\0'.                          */
/*     If global variable cipher_mode == 1, then each legal character read is */
/*     copied into * data.                                                    */
/*     If global variable cipher_mode == 0, then character codes [0, 31]      */
/*     and 127 might be represented as two-byte codes starting with '+'.      */
/*     This function converts any such two-character codes to the single      */
/*     ASCII code [0,127]. Therefore, this function may read as many as       */
/*     eight characters form the standard input stream.                       */
/*                                                                            */
/* Returns:                                                                   */
/*   OK | END_OF_LINE | END_OF_FILE | ERROR                                   */
/******************************************************************************/
int readDataBlock(char * data)
{
  int i;
  
  //Clear the array
  memset(data, 0, sizeof(char) * 5);
  
  //Populate the array from the standard input stream
  for (i = 0; i < 4; i++)
  {
    char active_char = getchar();
    
    if (active_char == '\n') return END_OF_LINE;
    else if (active_char == EOF) return END_OF_FILE;
    else if (!isascii(active_char))
    {
      if (DEBUG_ERROR)
      {
        printf("Error: Non-ASCII character read in a data block!\n");
      }
      return ERROR;
    }
    else * (data + i) = active_char;
  }
  
  return OK;
}



/******************************************************************************/
/* readCipherMode(void)                                                       */
/*   Reads one character from the standard input stream.                      */
/*   Sets the global variable cipher_mode to represent encryption or          */
/*   decryption determined by the read character being 'e' or 'd'.            */
/*                                                                            */
/* Returns:                                                                   */
/*   OK if an 'e' or 'd' was read.                                            */
/*   END_OF_LINE if '\n' was read.                                            */
/*   END_OF_FILE if EOF was read.                                             */
/*   otherwise ERROR.                                                         */
/******************************************************************************/
int readCipherMode(void)
{
  char mode = getchar();
  
  if (mode == 'e')
  {
    cipher_mode = 0;
    return OK;
  }
  if (mode == 'd')
  {
    cipher_mode = 1;
    return OK;
  }
  if (mode == '\n') return END_OF_LINE;
  if (mode == EOF) return END_OF_FILE;
  
  if (DEBUG_ERROR)
  {
    printf("Error: Invalid cipher mode!\n");
  }
  return ERROR;
}



/******************************************************************************/
/* readKey(void)                                                              */
/*   Initializes the linear congruental generator.                            */
/*                                                                            */
/* Return: OK | ERROR                                                         */
/******************************************************************************/
int buildLCG(void)
{
  //Calculate LCG_M
  lcg_m = readNumber(',');
  if (lcg_m <= 0)
  {
    if (DEBUG_ERROR)
    {
      printf("Error LCG_M = %llu and cannot be smaller than or equal to 0!\n",
             lcg_m);
    }
    return ERROR;
  }
  
  printf("");
  
  //Calculate LCG_C
  lcg_c = readNumber(',');
  if (lcg_c <= 0)
  {
    if (DEBUG_ERROR)
    {
      printf("Error LCG_C = %llu and cannot be smaller than or equal to 0!\n",
             lcg_c);
    }
    return ERROR;
  }
  
  //Calculate LCG_A
  calculatePrimeFactors(lcg_m);
  
  int i;
  max = 0;
  unsigned long long int p = 1;
  unsigned long long int last = 1;
  
  for (i = 0; i < 100; i++)
  {
    if (factors[i] != 0) max++;
    else break;
  }
  
  for (i = 0; i < max; i++)
  {
    if (last != factors[i])
    {
      last = factors[i];
      p *= factors[i];
    }
  }
  
  if (DEBUG_LCG)
  {
    printf("max: %d\n", max);
    printf("p: %llu\n", p);
  }
  
  if (lcg_m % 4 == 0) lcg_a = 1 + 2 * p;
  else lcg_a = 1 + p;
  
  if (lcg_a > lcg_m)
  {
    if (DEBUG_ERROR)
    {
      printf("Error LCG_A = %llu and cannot be larger than LCG_M = %llu\n",
             lcg_a, lcg_m);
    }
    return ERROR;
  }
  
  //Calculate LCG_X
  lcg_x = lcg_c;
  
  if (DEBUG_LCG)
  {
    printf("\nThe Linear Congruental Generator\n");
    printf("LCG_X: %llu\n", lcg_x);
    printf("LCG_A: %llu\n", lcg_a);
    printf("LCG_M: %llu\n", lcg_m);
    printf("LCG_C: %llu\n", lcg_c);
  }
  
  return OK;
}



/******************************************************************************/
/* buildMap(void)                                                             */
/*   Uses the global variables lcg_a, lcg_c, lcg_m and lcg_x to define the    */
/*   global array builtMap such that builtMap[i] = k indicates that on        */
/*   encryption, bit i is moved to bit k and the reverse on decryption.       */
/*                                                                            */
/*   When this function returns, lcg_x will have been updated 28 steps        */
/*   in the LCG.                                                              */
/*                                                                            */
/*   This method does not return a value because there is no reason for it    */
/*   to fail.                                                                 */
/******************************************************************************/
void buildMap(void)
{
  int g[MAP_LENGTH];
  int i;
  
  //Clear map and associated fields.
  memset(builtMap, 0, sizeof(int) * MAP_LENGTH);
  memset(assigned, 0, sizeof(int) * MAP_LENGTH);
  memset(assigned_index, 0, sizeof(int) * MAP_LENGTH);
  
  //Compute g(i)
  for (i = 0; i < MAP_LENGTH; i++)
  {
    g[i] = lcg_x % (MAP_LENGTH - i);
    lcg_x = ((lcg_a * lcg_x) + lcg_c) % lcg_m;
  }
  
  if (DEBUG_BUILDING_MAP)
  {
    printf("Building Map... g(i):\n");
    printf("%d", g[0]);
    for (i = 1; i < MAP_LENGTH; i++)
    {
      printf(", %d", g[i]);
    }
    printf("\n-----------------------------------------------------------\n");
  }
  
  //Compute f(i)
  for (i = 0; i < MAP_LENGTH; i++)
  {
    //Get the step size.
    int active_index = g[i];
    
    //Traverse free spaces n times where n is equal to the step size.
    int index = 0;
    int unassigned = 0;
    
    while (unassigned != active_index)
    {
      if (!assigned[index++]) unassigned++;
    }
    
    int placed = 0;
    
    while (!placed)
    {
      if (!assigned[index])
      {
        builtMap[i] = index;
        assigned[index] = 1;
        assigned_index[index] = i;
        placed = 1;
      }
      else index++;
    }
 
    if (DEBUG_BUILDING_MAP)
    {
      int j;
      
      printf("Building Map... f(%d):\n", i);
      printf("Step Size: g(%d) = %d\n", i, active_index);
      printf("Map\n");
      printf("%d", builtMap[0]);
      for (j = 1; j < MAP_LENGTH; j++)
      {
        printf(", %d", builtMap[j]);
      }
      printf("\n");
      printf("Assigned\n");
      printf("%d", assigned[0]);
      for (j = 1; j < MAP_LENGTH; j++)
      {
        printf(", %d", assigned[j]);
      }
      printf("\n");
      
      printf("Assigned Index\n");
      printf("%d", assigned_index[0]);
      for (j = 1; j < MAP_LENGTH; j++)
      {
        printf(", %d", assigned_index[j]);
      }
      printf("\n-----------------------------------------------------------\n");
    }
  }
}



/******************************************************************************/
/* isBitSet(char c, int n)                                                    */
/*   Indicates if the nth least significant of the provided character is      */
/*   turned on.                                                               */
/*                                                                            */
/* Parameters: c: The character to inspect.                                   */
/*                                                                            */
/* Return: An indicator representing the on/off status of the nth bit.        */
/******************************************************************************/
int isBitSet(char c, int n)
{
  return ((c & (1 << n)) != 0);
}



/******************************************************************************/
/* setBit(char * c, int n)                                                    */
/*   Sets the nth least significant bit of the provided character pointed to  */
/*   on.                                                                      */
/*                                                                            */
/* Parameters: * c: The character to set.                                     */
/******************************************************************************/
void setBit(char * c, int n)
{
  * c |= 1 << n;
}



/******************************************************************************/
/* encryptText(char * data)                                                   */
/*   Uses the global variable builtMap to encrypt the data block in * data.   */
/*   The encrypted data is sent to the standard output stream.                */
/*   The encrypted data will always be 4 to 8 bytes long.                     */
/*   Encrypted byte codes [0,31], 127 and '+' are converted to 2-byte         */
/*   printable ASCII characters.                                              */
/*                                                                            */
/* Parameters: * data: Must be a null terminated characater array of size 5.  */
/*                                                                            */
/* Return: OK | ERROR                                                         */
/******************************************************************************/
int encryptText(char * data)
{
  char * encrypted = malloc(sizeof(char) * 5);
  char * encrypted_formatted = malloc(sizeof(char) * 9);
  
  memset(encrypted, 0, sizeof(char) * 5);
  memset(encrypted_formatted, 0, sizeof(char) * 9);
  
  int i;
  
  /* If the data is null, then skip encryption */
  int empty_data_flag = 1;
  
  for (i = 0; i < 4; i++)
  {
    if (* (data + i)) empty_data_flag = 0;
  }
  
  if (empty_data_flag) return OK;
  /*********************************************/
  
  for (i = 0; i < 28; i++)
  {
    if (0)
    {
      printf("The builtMap[%d] = %d\n", i, builtMap[i]);
      printf("Is bit %d on data[%d] on? ––– %d\n",
             i % 7, i / 7, isBitSet(data[i / 7], i % 7));
    }
    
    if (isBitSet(data[i / 7], i % 7))
    {
      if (DEBUG_BUILT_MAP)
      {
        printf("Placing bit at index %d on encrypted[%d]\n",
               builtMap[i] % 7, builtMap[i] / 7);
        printf("(%d, %d) --> (%d, %d)\n\n", i % 7, i / 7, builtMap[i] % 7, builtMap[i] / 7);
      }
      setBit(&encrypted[builtMap[i] / 7], builtMap[i] % 7);
    }
  }
  
  int counter = 0;
  
  for (i = 0; i < 4; i++)
  {    
    if (encrypted[i] < 32)
    {
      encrypted_formatted[counter++] = '+';
      encrypted_formatted[counter++] = '@' + encrypted[i];
    }
    else if (encrypted[i] == 127)
    {
      encrypted_formatted[counter++] = '+';
      encrypted_formatted[counter++] = '&';
    }
    else if (encrypted[i] == '+')
    {
      encrypted_formatted[counter++] = '+';
      encrypted_formatted[counter++] = '+';
    }
    else
    {
      * (encrypted_formatted + counter++) = encrypted[i];
    }
  }
  
  if (DEBUG_ENCRYPT)
  {
    printf("\nPartially Encrypted ASCII: %d, %d, %d, %d\n",
           encrypted[0], encrypted[1], encrypted[2], encrypted[3]);
    
    printf("The Partially Encrypted Text: %s\n", encrypted);
    
    printf("\nCipher Text ASCII: %d, %d, %d, %d\n",
           encrypted_formatted[0], encrypted_formatted[1],
           encrypted_formatted[2], encrypted_formatted[3]);
    
    printf("The Cipher Text: %s\n", encrypted_formatted);
  }
  
  if (!DEBUG_ENCRYPT) printf("%s", encrypted_formatted);
  
  free(encrypted);
  free(encrypted_formatted);
  
  return OK;
}



/******************************************************************************/
/* decrypt(char * data)                                                       */
/*   Uses the global variable builtMap to decrypt the data block in * data.   */
/*   The decrypted data is sent to the standard output stream.                */
/*   The decrypted data will always be 1 to 4 bytes long.                     */
/*   If a decrypted character is '\0' it means that the data block was a      */
/*   parcial block from the end of the line. '\0' characters are not printed. */
/*   Any other decrypted byte that is not a printable ASCII character is an   */
/*   error.                                                                   */
/*                                                                            */
/* Parameters: * data: Must be a null terminated character array of size 5.   */
/*                                                                            */
/* Return: OK | ERROR                                                         */
/******************************************************************************/
int decryptText(char * data)
{
  char * decrypted = malloc(sizeof(char) * 9);
  char * decrypted_formatted = malloc(sizeof(char) * 5);
  
  memset(decrypted, 0, sizeof(char) * 5);
  memset(decrypted_formatted, 0, sizeof(char) * 5);
  
  int i;
  
  /* If the data is null, then skip decryption */
  int empty_data_flag = 1;
  
  for (i = 0; i < 4; i++)
  {
    if (* (data + i)) empty_data_flag = 0;
  }
  
  if (empty_data_flag) return OK;
  /*********************************************/
  
  for (i = 0; i < 4; i++)
  {
    if (data[i] == '+')
    {
      if (i < 3)
      {
        if (data[i + 1] == '+')
        {
          decrypted[i] = '+';
        }
        else if (data[i + 1] == '&')
        {
          decrypted[i] = 127;
        }
        else
        {
          decrypted[i] = data[i + 1] - '@';
        }
        
        int j;
        
        for (j = i + 1; j < 4; j++)
        {
          data[j] = data[j + 1];
        }
        
        data[3] = getchar();
      }
      else
      {
        char last = getchar();
        
        if (last == '+')
        {
          decrypted[i] = '+';
        }
        else if (last == '&')
        {
          decrypted[i] = 127;
        }
        else
        {
          decrypted[i] = last - '@';
        }
      }
    }
    else decrypted[i] = data[i];
  }
  
  for (i = 0; i < 28; i++)
  {
    if (0)
    {
      printf("The builtMap[%d] = %d\n", i, builtMap[i]);
      printf("Is bit %d (%d mod 7 = %d) in decrypted[%d (%d / 7 = %d)] on? ––– %d\n",
             builtMap[i] % 7, builtMap[i], builtMap[i] % 7, builtMap[i] / 7,
             builtMap[i], builtMap[i] / 7,
             isBitSet(decrypted[builtMap[i] / 7], builtMap[i] % 7));
    }
    
    if (isBitSet(decrypted[builtMap[i] / 7], builtMap[i] % 7))
    {
      if (DEBUG_BUILT_MAP)
      {
        printf("Placing bit at index %d on decrypted_formatted[%d]\n", i % 7, i / 7);
        printf("(%d, %d) --> (%d, %d)\n\n", builtMap[i] % 7, builtMap[i] / 7, i % 7, i / 7);
      }
      setBit(&decrypted_formatted[i / 7], i % 7);
    }
  }
  
  if (DEBUG_DECRYPT)
  {
    printf("Partially Decrypted ASCII: %d, %d, %d, %d\n",
           decrypted[0], decrypted[1], decrypted[2], decrypted[3]);
    
    printf("The Partially Decrypted Text: %s\n", decrypted);
    
    printf("\nPlain Text ASCII: %d, %d, %d, %d\n",
           decrypted_formatted[0], decrypted_formatted[1],
           decrypted_formatted[2], decrypted_formatted[3]);
    
    printf("The Plain Text: %s\n", decrypted_formatted);
  }
  
  for (i = 0; i < 4; i++)
  {
    if ((decrypted_formatted[i] > 0 && decrypted_formatted[i] < 32) ||
        decrypted_formatted[i] == 127)
    {
      if (DEBUG_ERROR)
      {
        printf("Decrypted decrypted_formatted[%d] is out of ASCII range: %d\n",
               i, decrypted_formatted[i]);
      }
      return ERROR;
    }
  }
  
  if (!DEBUG_DECRYPT) printf("%s", decrypted_formatted);

  free(decrypted);
  free(decrypted_formatted);
  
  return OK;
}



int main(void)
{
  int input_line_number = 0;
  status = CLEAR;
  
  char data[5];
  data[4] = '\0';
  
  while (status != END_OF_FILE)
  {
    status = CLEAR;
    input_line_number++;
    
    status = readCipherMode();
    if (DEBUG_GENERAL)
    {
      printf("\nreadCipherMode: mode = %d status = %d\n", cipher_mode, status);
    }
    
    if ((status & END_OF_FILE) == 0)
    {
      printf("%5d) ", input_line_number);
    }
    
    if (status == OK)
    {
      status = buildLCG();
      if (DEBUG_GENERAL)
      {
        printf ("\nKey: m = %llu c = %llu a = %llu x = %llu status = %d\n",
                lcg_m, lcg_c, lcg_a, lcg_x, status);
      }
    }
    
    while (status == OK)
    {
      buildMap();
      status = readDataBlock(data);
      if (DEBUG_GENERAL)
      {
        printf("\nreadDataBlock::data=%s status=%d\n", data, status);
      }
      
      if ((status & ERROR) == 0)
      {
        if (cipher_mode == 0)
        {
          status |= encryptText(data);
        }
        else
        {
          status |= decryptText(data);
        }
      }
    }
    
    if (status & ERROR)
    {
      puts("Error");
      skipToEndOfLine();
    }
    else puts("");
  }
  
  return EXIT_SUCCESS;
}