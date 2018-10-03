use failure::Error;
use std::fs::File;
use std::io::prelude::*;
use zip::ZipArchive;

pub fn load_file(filename: &str, size: usize) -> Result<Vec<u8>, Error> {
    let bytes = open_input(filename)?
        .take(size as u64)
        .bytes()
        .map(|c| c.unwrap())
        .collect::<Vec<_>>();
    Ok(bytes)
}

pub fn load_zip_entry(archivename: &str, entryname: &str, _size: usize) -> Result<Vec<u8>, Error> {
    let archive = File::open(archivename)?;
    let mut zip = ZipArchive::new(archive)?;
    let bytes = zip.by_name_raw(entryname)?;
    Ok(bytes)
}

// TODO: 返回 Vec<u8> 不是一个明智的选择, 文件太大可能会爆内存
pub fn open_input_zip_entry(archivename: &str, entryname: &str) -> Result<Vec<u8>, Error> {
    let archive = File::open(archivename)?;
    let mut zip = ZipArchive::new(archive)?;
    let bytes = zip.by_name_raw(entryname)?;
    Ok(bytes)
}

pub fn open_input(filename: &str) -> Result<Vec<u8>, Error> {
    let file = File::open(filename)?;
    let bytes = file.bytes().map(|b| b.unwrap()).collect::<Vec<_>>();
    Ok(bytes)
}

pub fn open_output(filename: &str) -> Result<File, Error> {
    Ok(File::create(filename)?)
}
