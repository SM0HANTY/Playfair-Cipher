import numpy as np
import re
import itertools
from collections import defaultdict
import string

class PlayfairCipher:
    def __init__(self, key, mode='standard'):
        self.mode = mode.lower()  # 'standard', 'row_wise', 'column_wise'
        self.key = key.upper().replace("J", "I")
        self.key_matrix = self._prepare_key_matrix()
    
    def _prepare_key_matrix(self):
        # Process key and create 5x5 matrix based on selected mode
        key = self.key
        key = re.sub(r'[^A-Z]', '', key)
        
        # Remove duplicate letters
        seen = set()
        key_unique = []
        for char in key:
            if char not in seen:
                key_unique.append(char)
                seen.add(char)
        
        # Add remaining alphabet letters
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        for char in alphabet:
            if char not in seen:
                key_unique.append(char)
        
        # Arrange based on mode
        if self.mode == 'standard':
            matrix = np.array(key_unique).reshape(5, 5)
        elif self.mode == 'row_wise':
            # Modified row-wise: reverse every other row
            matrix = np.array(key_unique).reshape(5, 5)
            for i in range(1, 5, 2):
                matrix[i] = matrix[i][::-1]
        elif self.mode == 'column_wise':
            # Fill column-wise
            matrix = np.array(key_unique).reshape(5, 5).T
        else:
            raise ValueError("Invalid mode. Choose 'standard', 'row_wise', or 'column_wise'")
        
        return matrix
    
    def _prepare_text(self, text):
        # Prepare text: remove non-alphabets, handle J/I, add X if needed
        text = text.upper().replace("J", "I")
        text = re.sub(r'[^A-Z]', '', text)
        
        # Split into digraphs and handle double letters
        digraphs = []
        i = 0
        while i < len(text):
            if i == len(text) - 1:
                digraphs.append(text[i] + 'X')
                break
            if text[i] == text[i+1]:
                digraphs.append(text[i] + 'X')
                i += 1
            else:
                digraphs.append(text[i] + text[i+1])
                i += 2
        return digraphs
    
    def _find_position(self, char):
        # Find the row and column of a character in the key matrix
        for i in range(5):
            for j in range(5):
                if self.key_matrix[i][j] == char:
                    return (i, j)
        raise ValueError(f"Character {char} not found in key matrix")
    
    def encrypt(self, plaintext):
        digraphs = self._prepare_text(plaintext)
        ciphertext = []
        
        for digraph in digraphs:
            a, b = digraph[0], digraph[1]
            row_a, col_a = self._find_position(a)
            row_b, col_b = self._find_position(b)
            
            # Same row
            if row_a == row_b:
                ciphertext.append(self.key_matrix[row_a][(col_a + 1) % 5])
                ciphertext.append(self.key_matrix[row_b][(col_b + 1) % 5])
            # Same column
            elif col_a == col_b:
                ciphertext.append(self.key_matrix[(row_a + 1) % 5][col_a])
                ciphertext.append(self.key_matrix[(row_b + 1) % 5][col_b])
            # Rectangle
            else:
                ciphertext.append(self.key_matrix[row_a][col_b])
                ciphertext.append(self.key_matrix[row_b][col_a])
        
        return ''.join(ciphertext)
    
    def decrypt(self, ciphertext):
        ciphertext = ciphertext.upper().replace("J", "I")
        ciphertext = re.sub(r'[^A-Z]', '', ciphertext)
        
        # Split into digraphs
        digraphs = [ciphertext[i:i+2] for i in range(0, len(ciphertext), 2)]
        plaintext = []
        
        for digraph in digraphs:
            a, b = digraph[0], digraph[1]
            row_a, col_a = self._find_position(a)
            row_b, col_b = self._find_position(b)
            
            # Same row
            if row_a == row_b:
                plaintext.append(self.key_matrix[row_a][(col_a - 1) % 5])
                plaintext.append(self.key_matrix[row_b][(col_b - 1) % 5])
            # Same column
            elif col_a == col_b:
                plaintext.append(self.key_matrix[(row_a - 1) % 5][col_a])
                plaintext.append(self.key_matrix[(row_b - 1) % 5][col_b])
            # Rectangle
            else:
                plaintext.append(self.key_matrix[row_a][col_b])
                plaintext.append(self.key_matrix[row_b][col_a])
        
        # Remove any padding X's that don't make sense
        plaintext_str = ''.join(plaintext)
        if plaintext_str[-1] == 'X':
            plaintext_str = plaintext_str[:-1]
        
        # Handle cases where X was added between double letters
        for i in range(1, len(plaintext_str)-1):
            if plaintext_str[i] == 'X' and plaintext_str[i-1] == plaintext_str[i+1]:
                plaintext_str = plaintext_str[:i] + plaintext_str[i+1:]
        
        return plaintext_str

class PlayfairCryptanalyzer:
    def __init__(self, ciphertext):
        self.ciphertext = ciphertext.upper().replace("J", "I")
        self.ciphertext = re.sub(r'[^A-Z]', '', self.ciphertext)
        self.digraph_freq = defaultdict(int)
        self._analyze_frequencies()
    
    def _analyze_frequencies(self):
        # Analyze digraph frequencies in ciphertext
        digraphs = [self.ciphertext[i:i+2] for i in range(0, len(self.ciphertext), 2)]
        for d in digraphs:
            self.digraph_freq[d] += 1
    
    def brute_force_attack(self, possible_keys, plaintext_sample=None):
        """
        Attempt decryption with possible keys
        plaintext_sample: a sample of plaintext to help identify correct decryption
        """
        results = []
        
        for key in possible_keys:
            for mode in ['standard', 'row_wise', 'column_wise']:
                try:
                    cipher = PlayfairCipher(key, mode)
                    decrypted = cipher.decrypt(self.ciphertext)
                    
                    # Score based on English letter frequencies if no sample provided
                    if plaintext_sample:
                        score = self._match_score(decrypted, plaintext_sample)
                    else:
                        score = self._english_score(decrypted)
                    
                    results.append({
                        'key': key,
                        'mode': mode,
                        'decrypted': decrypted,
                        'score': score
                    })
                except:
                    continue
        
        # Sort results by score (higher is better)
        results.sort(key=lambda x: x['score'], reverse=True)
        return results[:10]  # Return top 10 results
    
    def _match_score(self, decrypted, sample):
        """Score based on how much of the sample appears in decrypted text"""
        sample = sample.upper()
        score = 0
        for i in range(len(sample) - 3):
            if sample[i:i+4] in decrypted:
                score += 4
        return score
    
    def _english_score(self, text):
        """Score based on frequency of common English letters and digraphs"""
        common_letters = 'ETAOINSHRDLCUMWFGYPBVKJXQZ'
        common_digraphs = ['TH', 'HE', 'IN', 'ER', 'AN', 'RE', 'ND', 'AT', 'ON', 'NT']
        
        score = 0
        text = text.upper()
        
        # Score single letters
        for i, char in enumerate(common_letters):
            score += (26 - i) * text.count(char)
        
        # Score digraphs
        for i, digraph in enumerate(common_digraphs):
            score += (10 - i) * 5 * text.count(digraph)
        
        return score

def main():
    # Example usage
    print("Playfair Cipher Demonstration")
    print("============================")
    
    # Get user input
    key = input("Enter the key: ").strip()
    plaintext = input("Enter the plaintext: ").strip()
    mode = input("Choose mode (standard/row_wise/column_wise): ").strip().lower()
    
    # Encrypt
    cipher = PlayfairCipher(key, mode)
    encrypted = cipher.encrypt(plaintext)
    print(f"\nEncrypted text: {encrypted}")
    
    # Decrypt
    decrypted = cipher.decrypt(encrypted)
    print(f"Decrypted text: {decrypted}")
    
    # Verify
    if decrypted.replace('X', '') == plaintext.upper().replace('J', 'I').replace(' ', ''):
        print("Decryption successful!")
    else:
        print("Decryption had some issues with padding X's")
    
    # Cryptanalysis demonstration
    print("\nCryptanalysis Demonstration")
    print("===========================")
    analyzer = PlayfairCryptanalyzer(encrypted)
    
    # Generate some possible keys (in a real attack, this would be more sophisticated)
    possible_keys = [
        key,  # The actual key
        'EXAMPLE',  # Another possible key
        'SECRET',
        'KINGDOM',
        'MONARCHY'
    ]
    
    # Add some variations of the actual key
    for i in range(3):
        possible_keys.append(key[:i] + key[i+1:])
        possible_keys.append(key[:i] + key[i].lower() + key[i+1:])
    
    print("\nAttempting brute force attack with possible keys...")
    results = analyzer.brute_force_attack(possible_keys, plaintext[:10])
    
    print("\nTop 10 decryption attempts:")
    for i, result in enumerate(results, 1):
        print(f"{i}. Key: {result['key']}, Mode: {result['mode']}, Score: {result['score']}")
        print(f"   Decrypted: {result['decrypted']}\n")

if __name__ == "__main__":
    main()