use anyhow::{Result, bail, ensure};

pub(super) const MAX_REGEX_LEN: usize = 256;
const MAX_REGEX_STATES: usize = 128;
const MAX_REGEX_DEPTH: usize = 8;
const MAX_REGEX_REPEAT: usize = 16;

struct RegexParser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl RegexParser<'_> {
    const fn peek(&self) -> Option<u8> {
        if self.pos < self.bytes.len() { Some(self.bytes[self.pos]) } else { None }
    }

    fn next_byte(&mut self) -> Result<u8> {
        let Some(&byte) = self.bytes.get(self.pos) else {
            bail!("Unexpected end of URL regex");
        };
        self.pos += 1;
        Ok(byte)
    }

    fn parse_alt(&mut self, depth: usize, in_group: bool) -> Result<(bool, usize)> {
        let (mut nullable, mut cost) = self.parse_seq(depth, in_group)?;
        while self.peek() == Some(b'|') {
            self.pos += 1;
            let (branch_null, branch_cost) = self.parse_seq(depth, in_group)?;
            nullable |= branch_null;
            cost = cost.saturating_add(1).saturating_add(branch_cost);
            ensure!(cost < MAX_REGEX_STATES, "URL regex exceeds bounded NFA state limit");
        }
        Ok((nullable, cost))
    }

    fn parse_seq(&mut self, depth: usize, in_group: bool) -> Result<(bool, usize)> {
        let mut nullable = true;
        let mut cost = 0usize;
        let mut has_item = false;
        while let Some(byte) = self.peek() {
            if byte == b'|' || (in_group && byte == b')') {
                break;
            }
            ensure!(in_group || byte != b')', "Unmatched closing parenthesis in URL regex");
            let (atom_null, atom_cost, quantifiable) = self.parse_atom(depth)?;
            let (item_null, item_cost) = self.parse_quantifier(atom_null, atom_cost, quantifiable)?;
            has_item = true;
            nullable &= item_null;
            cost = cost.saturating_add(item_cost);
            ensure!(cost < MAX_REGEX_STATES, "URL regex exceeds bounded NFA state limit");
        }
        ensure!(has_item, "Empty expression in URL regex");
        Ok((nullable, cost))
    }

    fn parse_atom(&mut self, depth: usize) -> Result<(bool, usize, bool)> {
        let byte = self.next_byte()?;
        match byte {
            b'^' | b'$' => Ok((true, 1, false)),
            b'.' => Ok((false, 1, true)),
            b'*' | b'+' | b'?' | b'{' | b'}' => bail!("Unexpected quantifier or brace in URL regex"),
            b'(' => {
                ensure!(depth < MAX_REGEX_DEPTH, "URL regex exceeds group nesting limit");
                if self.peek() == Some(b'?') {
                    self.pos += 1;
                    ensure!(self.next_byte()? == b':', "Unsupported group modifier in URL regex");
                }
                let (nullable, cost) = self.parse_alt(depth + 1, true)?;
                ensure!(self.next_byte()? == b')', "Unclosed group in URL regex");
                Ok((nullable, cost, true))
            }
            b'[' => {
                self.parse_class()?;
                Ok((false, 1, true))
            }
            b'\\' => {
                let esc = self.next_byte()?;
                ensure!(matches!(esc, b'd' | b'D' | b'w' | b'W' | b's' | b'S') || !esc.is_ascii_alphanumeric(), "Unsupported escape in URL regex");
                Ok((false, 1, true))
            }
            _ => Ok((false, 1, true)),
        }
    }

    fn parse_class(&mut self) -> Result<()> {
        if self.peek() == Some(b'^') {
            self.pos += 1;
        }
        ensure!(self.peek().is_some_and(|b| b != b']'), "Empty or unclosed character class in URL regex");
        while self.peek().is_some_and(|b| b != b']') {
            let first = self.read_class_atom()?;
            if self.bytes.get(self.pos) == Some(&b'-') && self.bytes.get(self.pos + 1).is_some_and(|&b| b != b']') {
                self.pos += 1;
                let second = self.read_class_atom()?;
                let (Some(lo), Some(hi)) = (first, second) else {
                    bail!("Character class range requires literal bounds");
                };
                ensure!(lo <= hi, "Reversed character class range in URL regex");
            }
        }
        ensure!(self.next_byte()? == b']', "Unclosed character class in URL regex");
        Ok(())
    }

    fn read_class_atom(&mut self) -> Result<Option<u8>> {
        let byte = self.next_byte()?;
        ensure!(byte != b'[', "Unescaped '[' in character class");
        if byte != b'\\' {
            return Ok(Some(byte));
        }
        let esc = self.next_byte()?;
        if matches!(esc, b'd' | b'D' | b'w' | b'W' | b's' | b'S') {
            return Ok(None);
        }
        ensure!(!esc.is_ascii_alphanumeric(), "Unsupported escape in character class");
        Ok(Some(esc))
    }

    fn parse_quantifier(&mut self, atom_null: bool, atom_cost: usize, quantifiable: bool) -> Result<(bool, usize)> {
        let Some(op) = self.peek() else {
            return Ok((atom_null, atom_cost));
        };
        if !matches!(op, b'*' | b'+' | b'?' | b'{') {
            return Ok((atom_null, atom_cost));
        }
        ensure!(quantifiable && !atom_null, "Cannot quantify anchor or nullable expression in URL regex");
        self.pos += 1;
        let (min, max) = match op {
            b'*' => (0, None),
            b'+' => (1, None),
            b'?' => (0, Some(1)),
            _ => self.parse_counted_repeat()?,
        };
        if self.peek() == Some(b'?') {
            self.pos += 1;
        }
        ensure!(!self.peek().is_some_and(|b| matches!(b, b'*' | b'+' | b'?' | b'{')), "Chained quantifiers are unsupported in URL regex");
        let cost = match max {
            None => min.max(1).saturating_mul(atom_cost).saturating_add(1),
            Some(hi) => hi.saturating_mul(atom_cost).saturating_add(hi - min),
        };
        ensure!(cost < MAX_REGEX_STATES, "URL regex exceeds bounded NFA state limit");
        Ok((min == 0, cost))
    }

    fn parse_counted_repeat(&mut self) -> Result<(usize, Option<usize>)> {
        let min = self.parse_repeat_bound()?;
        match self.next_byte()? {
            b'}' => {
                ensure!(min >= 1, "Zero repetition is unsupported in URL regex");
                Ok((min, Some(min)))
            }
            b',' => {
                if self.peek() == Some(b'}') {
                    self.pos += 1;
                    return Ok((min, None));
                }
                let max = self.parse_repeat_bound()?;
                ensure!(self.next_byte()? == b'}' && min <= max && max >= 1, "Invalid bounded repetition in URL regex");
                Ok((min, Some(max)))
            }
            _ => bail!("Invalid repetition syntax in URL regex"),
        }
    }

    fn parse_repeat_bound(&mut self) -> Result<usize> {
        let start = self.pos;
        let mut value = 0usize;
        while let Some(digit) = self.peek().filter(u8::is_ascii_digit) {
            self.pos += 1;
            value = value.saturating_mul(10).saturating_add(usize::from(digit - b'0'));
            ensure!(value <= MAX_REGEX_REPEAT, "Repetition bound exceeds 16 in URL regex");
        }
        ensure!(self.pos > start, "Expected integer bound in URL regex");
        Ok(value)
    }
}

pub(super) fn validate_regex(pattern: Option<&str>) -> Result<()> {
    let Some(raw) = pattern else {
        return Ok(());
    };
    let bytes = raw.as_bytes();
    ensure!(!bytes.is_empty() && bytes.len() <= MAX_REGEX_LEN && bytes.iter().all(|b| (0x20..=0x7e).contains(b)), "URL regex must be 1..=256 printable ASCII bytes");
    let mut parser = RegexParser { bytes, pos: 0 };
    let (_, cost) = parser.parse_alt(0, false)?;
    ensure!(parser.pos == bytes.len() && cost + 1 <= MAX_REGEX_STATES, "Invalid or overly complex URL regex");
    Ok(())
}
