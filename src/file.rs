use failure::Error;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::mem;
use std::slice;
use super::utils::Zip;

fn read<T>(stream: &mut File, x: &mut T) -> Result<(), Error> {
    let size = mem::size_of::<T>();
    let x = unsafe { &mut *(slice::from_raw_parts_mut(x, size) as *mut [T] as *mut [u8]) };
    stream.read_exact(x)?;
    Ok(())
}

pub fn load_stream(is: &File, size: usize) -> Vec<u8> {
    is.take(size as u64)
        .bytes()
        .map(|c| c.unwrap())
        .collect::<Vec<_>>()
}

pub fn load_file(filename: &str, size: usize) -> Result<Vec<u8>, Error> {
    let is = open_input(filename)?;
    Ok(load_stream(&is, size))
}

pub fn load_zip_entry(archivename: &str, entryname: &str, size: usize) -> Result<Vec<u8>, Error> {
    let mut entrysize = 0usize;
    let is = open_input_zip_entry(archivename, entryname, &mut entrysize)?;
    Ok(load_stream(&is, entrysize.min(size)))
}

pub fn open_input(filename: &str) -> Result<File, Error> {
    Ok(File::open(filename)?)
}

pub fn open_input_zip_entry(
    archivename: &str,
    entryname: &str,
    size: &mut usize,
) -> Result<File, Error> {
    let mut is = open_input(archivename)?;

    // look for end of central directory
    is.seek(io::SeekFrom::End(-22))?; // start by assuming there is no comment
    let mut sig = 0u32;
    read(&mut is, &mut sig)?;
    is.seek(io::SeekFrom::Current(-4))?;
    while sig != Zip::EndLocator as u32 {
        is.seek(io::SeekFrom::Current(-1))?;
        read(&mut is, &mut sig)?;
        is.seek(io::SeekFrom::Current(-4))?;
    }

    let eocdoffset = is.seek(io::SeekFrom::Current(0))?; // end of central directory offset

    // read central directory offset
    let mut cdoffset = 0u32;
    is.seek(io::SeekFrom::Current(16))?;
    read(&mut is, &mut cdoffset)?;

    // iterate on each entry
    is.seek(io::SeekFrom::Start(u64::from(cdoffset)))?;
    let mut name = String::new();
    let (mut compressed_size, mut offset) = (0u32, 0u32);

    while name != entryname && is.seek(io::SeekFrom::Current(0))? != eocdoffset {
        let (mut name_size, mut extra_size, mut comment_size): (u16, u16, u16) = (0, 0, 0);

        is.seek(io::SeekFrom::Current(20))?;
        read(&mut is, &mut compressed_size)?;
        is.seek(io::SeekFrom::Current(4))?;
        read(&mut is, &mut name_size)?;
        read(&mut is, &mut extra_size)?;
        read(&mut is, &mut comment_size)?;
        is.seek(io::SeekFrom::Current(8))?;
        read(&mut is, &mut offset)?;

        let mut bytes = vec![0u8; name_size as usize];
        is.read_exact(&mut bytes)?;
        is.seek(io::SeekFrom::Current(i64::from(extra_size + comment_size)))?;

        name = bytes.iter().map(|&b| b as char).collect::<String>();
        //println!("{} {} {}", name, is.seek(io::SeekFrom::Current(0))?, eocdoffset);
    }

    if name != entryname {
        return Err(format_err!(
            "Could not find '{}' in archive '{}'",
            entryname,
            archivename
        ));
    }

    // read local file header
    let mut extra_size = 0u16;
    is.seek(io::SeekFrom::Start(u64::from(offset) + 28))?;
    read(&mut is, &mut extra_size)?;
    is.seek(io::SeekFrom::Current(
        name.len() as i64 + i64::from(extra_size),
    ))?;

    *size = compressed_size as usize;

    Ok(is)
}

pub fn open_output(filename: &str) -> Result<File, Error> {
    Ok(File::create(filename)?)
}
