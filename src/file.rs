use failure::Error;
use std::fs::{File, metadata};
use std::io::prelude::*;
use std::io::SeekFrom;
use zip::ZipArchive;

pub fn load_file(filename: &str, _size: usize) -> Result<Vec<u8>, Error> {
    let mut size = 0;
    let bytes = open_input(filename, &mut size)?
        .take(size as u64)
        .bytes()
        .map(|c| c.unwrap())
        .collect::<Vec<_>>();
    Ok(bytes)
}

pub fn load_zip_entry(archivename: &str, entryname: &str, _size: usize) -> Result<Vec<u8>, Error> {
    let archive = File::open(archivename)?;
    debug!("loading {}", archivename);
    let mut zip = ZipArchive::new(archive, true)?;
    debug!("searching {}", entryname);
    let bytes = zip.by_name_raw(entryname)?;
    Ok(bytes)
}

pub fn open_input_zip_entry(archivename: &str, entryname: &str, size: &mut usize) -> Result<File, Error> {
    let archive = File::open(archivename)?;
    debug!("loading {}", archivename);
    let zip = ZipArchive::new(archive, true)?;
    debug!("searching {}", entryname);
    let data = zip.by_name_meta(entryname)?;

    let archive = File::open(archivename)?;
    let zip = ZipArchive::new(archive, true)?;
    let mut reader = zip.into_inner();

    reader.seek(SeekFrom::Start(data.data_start))?;
    *size = data.uncompressed_size.max(data.compressed_size) as usize;
    debug!("file:{} size: {}", entryname, size);
    Ok(reader)
}

pub fn open_input(filename: &str, size: &mut usize) -> Result<File, Error> {
    let file = File::open(filename)?;
    let meta = metadata(filename)?;
    *size = meta.len() as usize;
    Ok(file)
}

pub fn open_output(filename: &str) -> Result<File, Error> {
    Ok(File::create(filename)?)
}
