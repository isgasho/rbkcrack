use failure::Error;
use std::fs::File;
use std::io::prelude::*;
use zip::ZipArchive;


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

pub fn load_zip_entry(
    archivename: &str,
    entryname: &str,
    _size: usize,
) -> Result<Vec<u8>, Error> {
    let archive = File::open(archivename)?;
    let mut zip = ZipArchive::new(archive)?;
    let bytes = zip.by_name_raw(entryname)?;
    Ok(bytes)
}

pub fn open_input(filename: &str) -> Result<File, Error> {
    Ok(File::open(filename)?)
}

pub fn open_output(filename: &str) -> Result<File, Error> {
    Ok(File::create(filename)?)
}
