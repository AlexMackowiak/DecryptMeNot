# DecryptMeNot
A tool to place a time-lock on a file using chained symmetric-key encryption. 

## Virtual Environment Installation
```
$ git clone https://github.com/AlexMackowiak/DecryptMeNot.git
$ cd DecryptMeNot
$ python3 -m venv .venv
$ source .venv/bin/activate
(.venv) $ pip3 install -r requirements.txt
```

## Usage
### Locking
```
python3 decrypt_me_not.py encrypt [file_path_to_encrypt] [duration]
```
`[file_path_to_encrypt]` - The path for the file to be time-locked.

`[duration]` - A duration string like `2h5m59s` ([or any format accepted by pytimeparse](https://github.com/wroberts/pytimeparse)) for the approximate length of time it should take to unlock the file.

#### Flags
`--out,-o [output_file_path]`
Specifies the output file path. If unspecified, the output file will be placed in the same directory as the input file but with `dnm_encrypted_` prepended to the input file's name.

`--with-pass,-p`
When set, the command will request the user to enter a password which will be used as an additional, final layer of encryption.

`--verbose,-v`
If provided, the command will print additional debug information about encryption progress.


### Unlocking
```
python3 decrypt_me_not.py decrypt [file_path_to_decrypt]
```
`[file_path_to_decrypt]` - A path to a file previously encrypted using `python3 decrypt_me_not.py encrypt`.

#### Flags
`--out,-o [output_file_path]`
Specifies the output file path. If unspecified, the output file will be placed in the same directory as the encrypted input file but with `decrypted_` prepended to the input file's name.

`--with-pass,-p`
When set, the command will attempt to decrypt the first layer of encryption with a password taken from the user. Necessary if and only if the original file was also encrypted using the `--with-pass` option.

`--verbose,-v`
If provided, the command will print additional debug information about decryption progress.

### Full Usage Example
```
(.venv) $ echo "testing full encrypt/decrypt pipeline 123" > testfile.txt
(.venv) $ python3 decrypt_me_not.py encrypt testfile.txt 5m --out encrypted_testfile.txt
(.venv) $ time python3 decrypt_me_not.py decrypt encrypted_testfile.txt --out decrypted_testfile.txt

real    5m16.231s
user    5m15.414s
sys     0m0.070s
(.venv) $ cat decrypted_testfile.txt
testing full encrypt/decrypt pipeline 123
(.venv) $ diff decrypted_testfile.txt testfile.txt
(.venv) $
```

## Caveats

 
 - Time-to-decrypt calculations are based only on timings from the encrypting computer. Other computers may therefore be faster or slower at decrypting the file.
    
 - Locked file time-to-decrypt is centered on the user-provided lock time, but still probabilistic. 
   - A file locked for 60s will have a 66% chance of decrypting within ±11s (49s to 71s).
   -  A file locked for 60s will have a 95% chance of decrypting within ±22s (38s to 82s).

 - For simplicity, the initial iteration of this program only operates on files small enough to fit in memory. It _would_ be possible to adapt this program to operate on file-blocks instead, allowing for arbitrary file sizes.

## Legitimate Use Cases
None
