/*
Following are examples of the pattern syntax. The syntax takes inspiration from YARA hexadecimal strings.

55 89 e5 83 ? ec
Case insensitive hexadecimal characters match the exact byte pattern and question marks serve as placeholders for unknown bytes.

Note that a single question mark matches a whole byte. The syntax to mask part of a byte is not yet available.

Spaces (code point 32) are completely optional and carry no semantic meaning, their purpose is to visually group things together.

b9 ' 37 13 00 00
Single quotes are used as a bookmarks, to save the current cursor rva in the save array passed to the scanner.

It is no longer necessary to do tedious address calculations to read information out of the byte stream after a match was found. This power really comes to life with the capability to follow relative and absolute references.

The first entry in the save array is reserved for the rva where the pattern was matched. The rest of the save array is filled in order of appearance of the quotes. Here the rva of the quote can be found in save[1].

b8 [16] 50 [13-42] ff
Pairs of decimal numbers separated by a hypen in square brackets indicate the lower and upper bound of number of bytes to skip. The scanner is non greedy and considers the first match while skipping as little as possible.

A single decimal number in square brackets without hypens is a fixed size jump, equivalent to writing that number of consecutive question marks.

31 c0 74 % ' c3
e8 $ ' 31 c0 c3
68 * ' 31 c0 c3
These symbols are used to follow; a signed 1 byte relative jump: %, a signed 4 byte relative jump: $ and an absolute pointer: *.

They are designed to be able to have the scanner follow short jumps, calls and longer jumps, and absolute pointers.

Composes really well with bookmarks to find the addresses of referenced functions and other data without tedious address calculations.

b8 * "STRING" 00
String literals appear in double quotes and will be matched as UTF-8.

Escape sequences are not supported, switch back to matching with hex digits as needed. For UTF-16 support, you are welcome to send a PR.

e8 $ { ' } 83 f0 5c c3
Curly braces must follow a jump symbol (see above).

The sub pattern enclosed within the curly braces is matched at the destination after following the jump. After the pattern successfully matched, the cursor returns to before the jump was followed. The bytes defining the jump are skipped and matching continues again from here.

e8 $ @4
Checks that the cursor is aligned at this point in the scan. The align value is (1 << arg), in this example the cursor is checked to be aligned to 16.

e8 i1 a0 u4
An i or u indicates memory read operations followed by the size of the operand to read.

The read values are stored in the save array alongside the bookmarked addresses (single quotes). This means the values are sign- or zero- extended respectively before being stored. Operand sizes are 1 (byte), 2 (word) or 4 (dword).

The cursor is advanced by the size of the operand.

83 c0 2a ( 6a ? | 68 ? ? ? ? ) e8
Parentheses indicate alternate subpatterns separated by a pipe character.

The scanner attempts to match the alternate subpatterns from left to right and fails if none of them match.
*/

#include <iostream>
#include <sstream>
#include <cstdint>
#include <vector>
#include <map>
#include <memory>
#include <stdexcept>

class PatternElement {
public:
    virtual ~PatternElement() {}
    virtual bool matches(uint8_t byte) const = 0;
};

class ByteElement : public PatternElement {
public:
    ByteElement(uint8_t byte) : byte_(byte) {}
    bool matches(uint8_t byte) const override {
        return byte_ == byte;
    }
    
    uint8_t getByte() const { return byte_; }
private:
    uint8_t byte_;
};

class WildcardElement : public PatternElement {
public:
    WildcardElement() {}
    bool matches(uint8_t byte) const override {
        return true;  // Wildcard matches any byte
    }
};

class BookmarkElement : public PatternElement {
public:
    BookmarkElement(const std::string& name) : name_(name) {}
    std::string getName() const { return name_; }
    bool matches(uint8_t byte) const override {
        // Bookmarks do not match any specific byte, so return false
        return false;
    }
private:
    std::string name_;
};

class JumpElement : public PatternElement {
public:
    JumpElement(int offset) : offset_(offset) {}
    int getOffset() const { return offset_; }
    bool matches(uint8_t byte) const override {
        // Jumps do not match any specific byte, so return false
        return false;
    }
private:
    int offset_;
};

class StringElement : public PatternElement {
public:
    StringElement(const std::string& str) : str_(str) {}
    std::string getString() const { return str_; }
    bool matches(uint8_t byte) const override {
        // String elements do not match a single byte, so return false
        return false;
    }
private:
    std::string str_;
};

class RangeJumpElement : public PatternElement {
public:
    RangeJumpElement(int lower, int upper) : lower_(lower), upper_(upper) {}
    int getLower() const { return lower_; }
    int getUpper() const { return upper_; }
    bool matches(uint8_t byte) const override {
        // Range jumps do not match any specific byte, so return false
        return false;
    }
private:
    int lower_;
    int upper_;
};

class AlternateSubpatternElement : public PatternElement {
public:
    AlternateSubpatternElement(std::vector<std::vector<PatternElement*>> subpatterns)
        : subpatterns_(std::move(subpatterns)) {}

    bool matches(uint8_t byte) const override {
        for (const auto& subpattern : subpatterns_) {
            bool match = true;
            for (const auto& element : subpattern) {
                if (!element->matches(byte)) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return true;
            }
        }
        return false;
    }

    const std::vector<std::vector<PatternElement*>>& getSubpatterns() const {
        return subpatterns_;
    }

private:
    std::vector<std::vector<PatternElement*>> subpatterns_;
};

class PatternScanner {
public:
    PatternScanner() {}

    std::map<std::string, size_t> getBookmarks() const {
        return bookmarks;
    }

    std::vector<size_t> scan(const std::string& pattern, const std::vector<uint8_t>& bytes) {
        std::vector<std::unique_ptr<PatternElement>> elements = parsePattern(pattern);
        std::map<std::string, size_t> bookmarks; 

        size_t elementIndex = 0;
        size_t matchStartIndex = 0;
        std::vector<size_t> matchPositions;

        for (size_t i = 0; i < bytes.size(); ++i) {
            if (elementIndex >= elements.size()) {
                matchPositions.push_back(matchStartIndex);
                elementIndex = 0;
                matchStartIndex = i;
            }

            PatternElement* element = elements[elementIndex].get();

            ByteElement* byteElement = dynamic_cast<ByteElement*>(element);
            WildcardElement* wildcardElement = dynamic_cast<WildcardElement*>(element);
            JumpElement* jumpElement = dynamic_cast<JumpElement*>(element);
            BookmarkElement* bookmarkElement = dynamic_cast<BookmarkElement*>(element);
            StringElement* stringElement = dynamic_cast<StringElement*>(element);
            RangeJumpElement* rangeJumpElement = dynamic_cast<RangeJumpElement*>(element);
            AlternateSubpatternElement* alternateSubpatternElement = dynamic_cast<AlternateSubpatternElement*>(element);

            if (alternateSubpatternElement != nullptr) {
                bool matchFound = false;
                for (const auto& subpattern : alternateSubpatternElement->getSubpatterns()) {
                    if (i + subpattern.size() > bytes.size()) {
                        continue;
                    }
                    bool match = true;
                    for (size_t j = 0; j < subpattern.size(); ++j) {
                        if (!subpattern[j]->matches(bytes[i + j])) {
                            match = false;
                            break;
                        }
                    }
                    if (match) {
                        i += subpattern.size() - 1;
                        ++elementIndex;
                        matchFound = true;
                        break;
                    }
                }
                if (!matchFound) {
                    elementIndex = 0;
                    matchStartIndex = i + 1;
                }
            } else if (stringElement != nullptr) {
                std::string str = stringElement->getString();
                if (std::equal(str.begin(), str.end(), bytes.begin() + i)) {
                    i += str.size() - 1;
                    ++elementIndex;
                } else {
                    elementIndex = 0;
                    matchStartIndex = i + 1;
                }
            } else if (rangeJumpElement != nullptr) {
                size_t j = i + rangeJumpElement->getLower();
                while (j <= i + rangeJumpElement->getUpper() && j < bytes.size()) {
                    if (elements[elementIndex + 1]->matches(bytes[j])) {
                        i = j;
                        ++elementIndex;
                        break;
                    }
                    ++j;
                }
                if (j > i + rangeJumpElement->getUpper() || j >= bytes.size()) {
                    elementIndex = 0;
                    matchStartIndex = i + 1;
                }
            } else if (bookmarkElement != nullptr) {
                bookmarks[bookmarkElement->getName()] = i;
                ++elementIndex;
            } else if (byteElement != nullptr && byteElement->getByte() == bytes[i]) {
                ++elementIndex;
            } else if (wildcardElement != nullptr) {
                ++elementIndex;
            } else if (jumpElement != nullptr) {
                i += jumpElement->getOffset();
                ++elementIndex;
            } else {
                elementIndex = 0;
                matchStartIndex = i + 1;
            }
        }

        return matchPositions;
    }

private:
    std::vector<std::unique_ptr<PatternElement>> parsePattern(const std::string& pattern) {
        std::vector<std::unique_ptr<PatternElement>> elements;
        std::istringstream iss(pattern);
        std::string token;

        while (iss >> token) {
            if (token == "?") {
                elements.push_back(std::make_unique<WildcardElement>());
            } else if (token[0] == '\'') { 
                std::string name = token.substr(1);
                elements.push_back(std::make_unique<BookmarkElement>(name));
            } else if (token[0] == 'j') {
                int offset = std::stoi(token.substr(1));
                elements.push_back(std::make_unique<JumpElement>(offset));
            } else if (token[0] == '[') {
                if (token.find('-') != std::string::npos) {
                    int lower = std::stoi(token.substr(1, token.find('-') - 1));
                    int upper = std::stoi(token.substr(token.find('-') + 1, token.size() - token.find('-') - 2));
                    elements.push_back(std::make_unique<RangeJumpElement>(lower, upper));
                } else {
                    int offset = std::stoi(token.substr(1, token.size() - 2));
                    elements.push_back(std::make_unique<JumpElement>(offset));
                }
            } else if (token[0] == '"') {
                std::string str = token.substr(1, token.size() - 2);
                elements.push_back(std::make_unique<StringElement>(str));
            } else if (token[0] == '(') {
                // Parse alternate subpatterns
                std::vector<std::unique_ptr<PatternElement>> currentSubpattern;
                std::vector<std::vector<std::unique_ptr<PatternElement>>> subpatterns;
                std::string subToken;

                while (iss >> subToken && subToken[0] != ')') {
                    if (subToken[0] == '|') {
                        subpatterns.push_back(std::move(currentSubpattern));
                        currentSubpattern = std::vector<std::unique_ptr<PatternElement>>();
                    } else {
                        std::istringstream subIss(subToken);
                        std::string elementToken;
                        while (subIss >> elementToken) {
                            if (elementToken == "?") {
                                currentSubpattern.push_back(std::make_unique<WildcardElement>());
                            } else {
                                try {
                                    uint8_t byte = static_cast<uint8_t>(std::stoi(elementToken, nullptr, 16));
                                    currentSubpattern.push_back(std::make_unique<ByteElement>(byte));
                                } catch (const std::invalid_argument& e) {
                                    throw std::runtime_error("Invalid pattern element: " + elementToken);
                                }
                            }
                        }
                    }
                }
                subpatterns.push_back(std::move(currentSubpattern));
                elements.push_back(std::make_unique<AlternateSubpatternElement>(std::move(subpatterns)));
            } else {
                try {
                    uint8_t byte = static_cast<uint8_t>(std::stoi(token, nullptr, 16));
                    elements.push_back(std::make_unique<ByteElement>(byte));
                } catch (const std::invalid_argument& e) {
                    throw std::runtime_error("Invalid pattern element: " + token);
                }
            }
        }

        return elements;
    }

    std::map<std::string, size_t> bookmarks;
};