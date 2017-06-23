import string
from fractions import gcd
from ciphers import Cipher


class Utilities():
    def main_menu(self):
        '''Displays the main menu of the program and helps to choose correct option
        for further actions.
        '''
        print("\nWelcome! Cipher / decipher methods:\n")
        print("1. Affine Cipher")
        print("2. Atbash Cipher")
        print("3. Transposition Cipher")
        print("4. Quit")
        while True:
            choice = ''
            choice = input('\nChoose a cipher method (1, 2, or 3): ')
            try:
                choice = int(choice)
                if choice == 1 or choice == 2 or choice == 3 or choice == 4:
                    return choice
                else:
                    print('\n\t\t\tINVALID CHOICE!!!')
                    continue
            except ValueError:
                print('\n\t\t\tINVALID INPUT!!!')
                continue

    def action_menu(self, current_cipher):
        '''Helps to choose correct action:
            Encode a message or
            Decode a message or
            Go back to main menu.
        '''
        print('\n{} Cipher. What next? '.
              format(current_cipher.__class__.__name__))
        print("\n1. Encode")
        print("2. Decode")
        print("3. Quit")
        while True:
            action = input('\nChoose action (1, 2, or 3): ')
            try:
                return int(action)
            except ValueError:
                print('\n\t\t\tINVALID INPUT!!!')
                continue

    def choose_action(self, current_cipher):
        '''Depending on chosen action and the selected cipher method
        from main menu, this takes user to the right action and right cipher.
        '''
        action = self.action_menu(current_cipher)
        if action == 1 or action == 2:
            self.make_message(action, current_cipher)
        elif action == 3:
            main()

    def make_message(self, action, current_cipher):
        '''Helps user to type in the message to encode/decode.
        Keeps the encoded message in the current cipher object.
        '''
        if action == 1:
            text = self.check_special_character()
            if len(text) > 0:
                current_cipher.encoded_message = self.msg_in_blocks(
                    current_cipher.encrypt(text), 5)
                print('\n\tEncoded Text (using {} Cipher): \n\t\t{}'.
                      format(current_cipher.__class__.__name__,
                             current_cipher.encoded_message))
            else:
                print('\nNon text to ENCODE!')
        elif action == 2:
            text = input('\nText to DECODE: ')
            text = self.remake_otp_coded_msg(text)
            if len(text) > 0:
                print('\n\tDecoded message (using {} Cipher): \n\t\t{}'.
                      format(current_cipher.__class__.__name__,
                             current_cipher.decrypt(text)))
            elif len(current_cipher.encoded_message) > 0:
                print('\n\tEncoded Text: \n\t{}'.
                      format(current_cipher.encoded_message))
                print('\n\tDecoded message (using {} Cipher): \n\t{}'.format(
                    current_cipher.__class__.__name__,
                    current_cipher.decrypt(self.remake_otp_coded_msg(
                        current_cipher.encoded_message))))
            else:
                print('\nNon text to DECODE!')
        self.choose_action(current_cipher)

    def check_special_character(self):
        while True:
            text = input('\nPlease enter the text to ENCODE: ')
            if len(text) < 1:
                continue
            else:
                has_special_char = False
                for ch in text:
                    if ch == 'ß' or ch == 'Ø':
                        print("\n\n\t\t\t'ß' and 'Ø' are special characters.")
                        print("\t\t\tPlease, remove them from the message.")
                        has_special_char = True
            if has_special_char:
                continue
            return text

    def first_secret(self):
        '''Gives user the ability to set the FIRST key, if the selected
        cipher is "Affice Cipher"
        '''
        while True:
            print('\nEnter number having 1 as greatest common divisor with 26')
            print('Example: 1, 3, 7, 101, 707, ...')
            first_secret = input('\nFIRST SECRET: ')
            try:
                first_secret = int(first_secret)
                if gcd(first_secret, 26) != 1:
                    continue
                else:
                    return first_secret
            except ValueError:
                print('INVALID INPUT!!!')
                continue

    def second_secret(self):
        '''Gives user the ability to set the SECOND key, if the selected
        cipher is "Affice Cipher"
        '''
        while True:
            print('\nEnter a number between 0 and 25.')
            print('Example: 0, 1, 2, ..., 24, 25.')
            second_secret = input('\nSECOND SECRET: ')
            try:
                second_secret = int(second_secret)
                if second_secret >= 0 and second_secret <= 25:
                    return second_secret
                else:
                    continue
            except ValueError:
                print('INVALID INPUT!!!')
                continue

    def msg_in_blocks(self, text, block_len):
        '''Displays the encoded message in blocks of five characters each.
        '''
        msg = ''
        block_len = int(block_len)
        text = text.replace(' ', 'ß')
        text = text + 'Ø' * (block_len - (len(text) % block_len))
        blocks = [text[i:i+block_len] for i in range(0, len(text), block_len)]
        for block in blocks:
            msg = msg + block + ' '
        return msg

    def remake_otp_coded_msg(self, text):
        '''Re-constitute the message as it was
        before formatting of display.
        '''
        text = text.replace(' ', '')
        text = text.replace('ß', ' ')
        text = text.replace('Ø', '')
        return text


class OneTimePad():
    alphabet = string.ascii_uppercase

    def char_to_num(self, char):
        '''Returns a number representing an letter from english alphabet.
        '''
        num = 0
        for letter in self.alphabet:
            if letter == char:
                break
            else:
                num += 1
        return num

    def num_to_char(self, num):
        '''Returns a letter represented by the provided number as argument.
        '''
        return self.alphabet[num]

    def encode_char(self, text, key):
        '''Takes two arguments: a letter as text and chosen one-time pad as a key.
        Encodes the letter using the provided key.
        Returns the code number of the letter.
        '''
        code_num = (self.char_to_num(text) + self.char_to_num(key)) % 26
        coded_text = self.num_to_char(code_num)
        return coded_text

    def decode_char(self, coded_text, key):
        '''Takes two arguments: a letter as coded text and chosen
        one-time pad as a key.
        Decodes the coded text using the provided key.
        Returns the corresponding letter.
        '''
        plain_num = self.char_to_num(coded_text) - self.char_to_num(key)
        plain_text = self.num_to_char(plain_num)
        return plain_text

    def encode(self, plain_text, key):
        '''Takes two arguments: a text and chosen one-time pad as a key.
        Encodes the text (one letter at a time) using the provided key.
        Constucts encoded text using each encoded letter
        Returns the encoded text.
        '''
        coded_text = ""
        j = 0
        for i in range(0, len(plain_text)):
            try:
                self.alphabet.index(plain_text[i])
                coded_text += self.encode_char(plain_text[i], key[j])
            except ValueError:
                coded_text += plain_text[i]
            j += 1
            if j >= len(key):
                j = 0

        return coded_text

    def decode(self, coded_text, key):
        '''Takes two arguments: a coded text and chosen one-time pad as a key.
        Decodes the coded text (one letter at a time) using the provided key.
        Constucts plain text using each decoded letter
        Returns the plain text.
        '''
        plain_text = ""
        j = 0
        for i in range(0, len(coded_text)):
            try:
                self.alphabet.index(coded_text[i])
                plain_text += self.decode_char(coded_text[i], key[j])
            except ValueError:
                plain_text += coded_text[i]
            j += 1
            if j >= len(key):
                j = 0
        return plain_text

    def make_otp_key(self, text):
        '''Takes one arguments: a text to be encoded.
        Asks for one-time pad and checks if it suitable with the text to encode
        Returns the one-time pad.
        '''
        text = text.replace(' ', '')
        while True:
            otp_key = input('\nEnter your One-Time Pad: ')
            otp_key = otp_key.upper()
            if len(otp_key) < 1 or len(otp_key) > len(text):
                print('\nOne-Time Pad lenght is between one and {} characters'.
                      format(len(text)))
                continue
            if self.check_otp_alphabet(otp_key):
                return otp_key
            else:
                continue

    def check_otp_alphabet(self, otp_key):
        for char in otp_key:
            try:
                self.alphabet.index(char)
            except ValueError:
                print('\nOne-Time Pad should be made of characters')
                print('from english alphabet (A - Z)')
                return False
        return True


class Affine(Cipher):
    encoded_message = ''
    alphabet = string.ascii_uppercase

    def __init__(self, first_secret, second_secret):
        '''Initializes the Affine object with suitable keys.
        '''
        self.first_secret = first_secret
        self.second_secret = second_secret

    def encrypt(self, text):
        '''Takes one arguments: a text to be encrypted.
        Encodes the text using one-time pad
        Endodes, using affine's provided secrets, the result from previous step
        Returns encoded text.
        '''
        otp = OneTimePad()
        text = text.upper()
        otp_key = otp.make_otp_key(text)
        text = otp.encode(text, otp_key)

        output = []
        for char in text:
            try:
                index = self.alphabet.index(char)
            except ValueError:
                output.append(char)
            else:
                output.append(self.alphabet[((self.first_secret * index) +
                                             self.second_secret) % 26])
        return ''.join(output)

    def decrypt(self, text):
        '''Takes one arguments: a text to be decrypted.
        Dedodes the text using affine's provided secrets.
        Decodes, using one-time pad, the result from previous step
        Returns decoded text.
        '''
        number = 0
        while True:
            inverse = self.first_secret * number % 26
            if inverse == 1:
                break
            number = number + 1

        otp = OneTimePad()
        text = text.upper()
        otp_key = otp.make_otp_key(text)

        output = []
        for char in text:
            try:
                index = self.alphabet.index(char)
            except ValueError:
                output.append(char)
            else:
                output.append(self.alphabet[number * (index - self.
                                                      second_secret) % 26])

        text = ''.join(output)
        text = otp.decode(text, otp_key)
        return text


class Atbash(Cipher):
    encoded_message = ''
    alphabet = string.ascii_uppercase
    reverse_alphabet = alphabet[::-1]

    def encrypt(self, text):
        '''Takes one arguments: a text to be encrypted.
        Encodes the text using one-time pad
        Endodes the result from previous step
        Returns encoded text.
        '''
        otp = OneTimePad()
        text = text.upper()
        otp_key = otp.make_otp_key(text)
        text = otp.encode(text, otp_key)

        output = []
        for char in text:
            try:
                index = self.alphabet.index(char)
            except ValueError:
                output.append(char)
            else:
                output.append(self.reverse_alphabet[index])
        return ''.join(output)

    def decrypt(self, text):
        '''Takes one arguments: a text to be decrypted.
        Dedodes the text.
        Decodes, using one-time pad, the result from previous step
        Returns decoded text.
        '''
        otp = OneTimePad()
        text = text.upper()
        otp_key = otp.make_otp_key(text)

        output = []
        for char in text:
            try:
                index = self.reverse_alphabet.index(char)
            except ValueError:
                output.append(char)
            else:
                output.append(self.alphabet[index])

        text = ''.join(output)
        text = otp.decode(text, otp_key)
        return text


class Transposition(Cipher):
    encoded_message = ''
    secret = 0

    def choose_secret(self, text):
        '''Takes one arguments: a text to be decrypted.
        Checks if the text is long enough to be decoded / encoded
        using transposition cipher.
        Asks for suitable key given the text.
        Checks if the provide key is suitable given the text.
        Sets the trasposition object's secret to be equal to the provided key.
        '''
        lenght_text = len(text)
        if lenght_text % 2 != 0:
            lenght_text += 1

        if lenght_text < 4:
            print('Text too short for Transposition Cipher')
            utilities = Utilities()
            utilities.choose_action(self)

        while True:
            secret = input('\nEnter SECRET key: ')
            try:
                secret = int(secret)
                if secret < 2 or secret > lenght_text / 2:
                    print('\nThat is not a SUITABLE KEY given the text!')
                    print('SUITABLE KEY should be a number between 2 and {} '.
                          format(int(lenght_text / 2)))
                    continue
                else:
                    self.secret = secret
                    break
            except ValueError:
                print('\nINVALID INPUT!!!')
                print('SUITABLE KEY should be a number between 2 and {} '.
                      format(int(lenght_text / 2)))
                continue

    def encrypt(self, text):
        '''Takes one arguments: a text to be encrypted.
        Encodes the text using one-time pad
        Endodes, using transposition's provided key,
        the result from previous step
        Returns encoded text.
        '''
        otp = OneTimePad()
        text = text.upper()
        otp_key = otp.make_otp_key(text)
        text = otp.encode(text, otp_key)

        self.choose_secret(text)
        index = 0
        step = 0
        output = []
        for char in text:
            output.append(text[index])
            index += self.secret
            if index > len(text) - 1:
                step += 1
                index = step
        return ''.join(output)

    def decrypt(self, text):
        '''Takes one arguments: a text to be decrypted.
        Dedodes the text using transpositon cipher's provided key.
        Decodes, using one-time pad, the result from previous step
        Returns decoded text.
        '''
        otp = OneTimePad()
        text = text.upper()
        otp_key = otp.make_otp_key(text)

        self.choose_secret(text)
        output = [''] * len(text)
        index = 0
        step = 0
        for char in text:
            output[index] = char
            index += self.secret
            if index > len(text) - 1:
                step += 1
                index = step

        text = ''.join(output)
        text = otp.decode(text, otp_key)
        return text


def main():
    '''Start utilities to run the program by giving main menu otions.
    Depending on the choosen option, sends user to appropriate cipher method.
    Or quit / ends the program
    '''
    utilities = Utilities()
    menu = utilities.main_menu()
    if menu == 1:
        print("\n\t\t\tAffine Cipher")
        print("\t\t\t=============\n")
        cipher = Affine(utilities.first_secret(), utilities.second_secret())
        utilities.choose_action(cipher)
    elif menu == 2:
        print("\n\t\t\tAtbash Cipher")
        print("\t\t\t=============\n")
        cipher = Atbash()
        utilities.choose_action(cipher)
    elif menu == 3:
        print("\n\t\t\tTransposition Cipher")
        print("\t\t\t===================\n")
        cipher = Transposition()
        utilities.choose_action(cipher)
    elif menu == 4:
        print("\n\t\t\t======= See you next time. Good bye! =======")


if __name__ == '__main__':
    main()
