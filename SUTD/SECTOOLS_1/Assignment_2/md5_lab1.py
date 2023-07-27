import argparse
import hashlib
import itertools
import string
import time
import random

parser=argparse.ArgumentParser()

parser.add_argument("-i", action="store", dest="input_file", help="For input file of md5 hashes")
parser.add_argument("-w", action="store", dest="wordlist_file", help="For plaintext wordlist")
parser.add_argument("-o", action="store", dest="output_file",help="Name of output file")
parser.add_argument('-b', action='store_true',help="-b to enable brute force, and no flag for dictionary attack")     #True for brute force, false for Dictionary attack

args=parser.parse_args()

input = open(args.input_file,"r")
wordlist = open(args.wordlist_file,"r")


wordlist_parsed=[]
hashed_wordlist=[]
input_list =[]
counter = 0

brute_dict={}

saltedPlaintext=[]
saltedHash=[]

sample_space=list(string.ascii_lowercase)

sample_space.extend(range(10))
#print(sample_space)
#print(args.b)

for line in wordlist:
    line = line.strip("\n")
    wordlist_parsed.append(line)
    #print(line)
    hashed = hashlib.md5(line.encode()).hexdigest()
    hashed_wordlist.append(hashed)

for line in input:
    line = line.strip("\n")
    input_list.append(line)

if not args.b:
    with open(args.output_file, 'w') as file:
        t0 = time.time()
    

        for i in range(len(input_list)):
            for j in range(len(hashed_wordlist)):
                if (input_list[i] == hashed_wordlist[j]):
                    print(f'{wordlist_parsed[j]} : {input_list[i]}')
                    file.write(f'{wordlist_parsed[j]} : {input_list[i]}\n')
                    counter+=1
                    break
        t1 = time.time()

        

        print(f'\n[{counter}] out of [{len(input_list)}] passwords cracked')

        print(f'Time taken for dict attack: {t1-t0}s\n')

        file.write(f'\n[{counter}] out of [{len(input_list)}] passwords cracked\n')
        file.write(f'Time taken for dict attack: {t1-t0}s\n')

else:

    print(f'Brute force attack in progress. Please wait...')
    with open(args.output_file, 'w') as file:
        t0 = time.time()

        for line in itertools.product(sample_space,repeat=5):
            line=(str(x) for x in line)
            line=''.join(line)
            hashed = hashlib.md5(line.encode()).hexdigest()
            brute_dict[line] = hashed
            

        for i in range(len(input_list)):
            for j in brute_dict:
                if (input_list[i] == brute_dict[j]):
                    print(f'{j} : {brute_dict[j]}')
                    file.write(f'{j} : {brute_dict[j]}\n')
                    saltedPlaintext.append(j)   #Still unsalted. Salt in next step
                    counter+=1
                    break
            
        t1 = time.time()

        print(f'\nTotal time taken: {t1-t0}s')
        file.write(f'\nTotal time taken: {t1-t0}s')

with open('pass6.txt','w') as file:
    
    for i in range(len(saltedPlaintext)):
        saltedPlaintext[i] = saltedPlaintext[i]+random.choice(string.ascii_lowercase)
        file.write(f'{saltedPlaintext[i]}\n')
        print(saltedPlaintext[i])


with open('salted6.txt','w') as file:

    for line in saltedPlaintext:
        hashed = hashlib.md5(line.encode()).hexdigest()
        file.write(f'{hashed}\n')