use failure::{format_err, Error};
use log::debug;
use podio::ReadPodExt;
use std::collections::HashMap;
use std::fs::{metadata, File};
use std::io::prelude::Seek;
use std::io::SeekFrom;
use zip::ZipArchive;

fn load_stream(stream: &mut File, size: u64) -> Result<Vec<u8>, Error> {
    Ok(stream.read_exact(size as usize)?)
}

/// 自动根据 CRC32 值寻找匹配的文件
pub fn auto_load_file(plain_zip: &str, cipher_zip: &str) -> Result<(Vec<u8>, Vec<u8>), Error> {
    println!("Searching automatically...");
    let mut plain_zip = ZipArchive::new(File::open(plain_zip)?)?;
    let mut cipher_zip = ZipArchive::new(File::open(cipher_zip)?)?;

    // 建立 crc32 - index 的索引
    let map = (0..plain_zip.len())
        .map(|i| {
            let file = plain_zip.by_index(i).unwrap();
            (file.crc32(), i)
        })
        .collect::<HashMap<_, _>>();

    // 遍历 cipher_zip, 寻找 crc32 匹配的文件
    for i in 0..cipher_zip.len() {
        let file = cipher_zip.by_index(i).unwrap();
        if let Some(index) = map.get(&file.crc32()) {
            // 提前获取 data_start, compressed_size 以取悦 borrow checker
            let (data_start, plain_size) = {
                let file = plain_zip.by_index(*index).unwrap();
                println!("Found plain: {}", file.name());
                (file.data_start(), file.compressed_size())
            };
            let mut plain = plain_zip.into_inner();
            plain.seek(SeekFrom::Start(data_start))?;

            // 此处因为 file 定义在外层, 只能主动 drop 以通过 borrow check
            let data_start = file.data_start();
            let cipher_size = file.compressed_size();
            println!("Found cipher: {}", file.name());
            drop(file);
            let mut cipher = cipher_zip.into_inner();
            cipher.seek(SeekFrom::Start(data_start))?;

            return Ok((
                plain.read_exact(plain_size as usize)?,
                cipher.read_exact(cipher_size as usize)?,
            ));
        }
    }
    Err(format_err!("could not find matched files"))
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
    let mut zip = ZipArchive::new(archive)?;
    debug!("searching {}", entryname);

    let data_start = {
        let zip_file = zip.by_name(entryname)?;
        *size = zip_file.compressed_size() as usize;
        zip_file.data_start()
    };

    let mut reader = zip.into_inner();
    reader.seek(SeekFrom::Start(data_start))?;

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
