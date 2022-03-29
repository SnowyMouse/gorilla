// Convert an i16 array to a u8, where any numbers out-of-bounds of a u8 are converted to None
macro_rules! sig {
    ( $( $x:expr ),* ) => {
        {
            trait MakeOpt {
                fn int_to_opt(&self) -> Option<u8>;
            }
            impl MakeOpt for i16 {
                fn int_to_opt(&self) -> Option<u8> {
                    if(*self < u8::MIN as i16 || *self > u8::MAX as i16) {
                        None
                    }
                    else {
                        Some((*self) as u8)
                    }
                }
            }

            let mut temp_vec = Vec::<Option<u8>>::new();
            $(
                temp_vec.push(($x).int_to_opt());
            )*
            temp_vec
        }
    };
}

/// Scan the data array for the signature, returning the offset (if found)
pub fn signature_scan(data : &[u8], signature : &[Option<u8>]) -> Option<usize> {
    // Ensure it's a valid signature?
    assert!(signature.len() > 0 || signature[0] == None || signature[signature.len() - 1] == None, "Signature may not be empty or start/end with a None");

    // Is our signature too big?
    if signature.len() > data.len() {
        return None
    }

    // Now let's look for it
    'sig_loop: for i in 0..data.len() - signature.len() {
        for j in 0..signature.len() {
            match signature[j] {
                Some(n) => if n != data[i+j] {
                    continue 'sig_loop
                },
                None => ()
            }
        }
        return Some(i);
    }

    None
}
