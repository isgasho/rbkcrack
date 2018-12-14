use failure::Error;
use log::debug;
use podio::ReadPodExt;
use std::fs::{metadata, File};
use std::io::prelude::Seek;
use std::io::SeekFrom;
use zip::ZipArchive;

fn load_stream(stream: &mut File, size: u64) -> Result<Vec<u8>, Error> {
    Ok(stream.read_exact(size as usize)?)
}

pub fn open_raw_file(filename: &str, size: &mut usize) -> Result<File, Error> {
    let file = File::open(filename)?;
    let meta = metadata(filename)?;
    *size = meta.len() as usize;
    Ok(file)
}

pub fn load_raw_file(filename: &str, size: usize) -> Result<Vec<u8>, Error> {
    let mut real_size = 0;
    let mut file = open_raw_file(filename, &mut real_size)?;
    let bytes = load_stream(&mut file, size.min(real_size) as u64)?;
    Ok(bytes)
}

pub fn open_zip_entry(archivename: &str, entryname: &str, size: &mut usize) -> Result<File, Error> {
    let archive = File::open(archivename)?;
    debug!("loading {}", archivename);
    let zip = ZipArchive::new(archive, true)?;
    debug!("searching {}", entryname);
    let data = zip.by_name_meta(entryname)?;

    let archive = File::open(archivename)?;
    let zip = ZipArchive::new(archive, true)?;
    let mut reader = zip.into_inner();

    reader.seek(SeekFrom::Start(data.data_start))?;
    *size = data.compressed_size as usize;
    debug!("Found! size: {}", size);
    Ok(reader)
}

pub fn load_zip_entry(archivename: &str, entryname: &str, size: usize) -> Result<Vec<u8>, Error> {
    let mut real_size = 0;
    let mut file = open_zip_entry(archivename, entryname, &mut real_size)?;
    let bytes = load_stream(&mut file, size.min(real_size) as u64)?;
    Ok(bytes)
}

pub fn open_output(filename: &str) -> Result<File, Error> {
    Ok(File::create(filename)?)
}
