use failure::{format_err, Error};
use log::debug;
use podio::ReadPodExt;
use std::collections::HashMap;
use std::fs::{metadata, File};
use std::io::prelude::Seek;
use std::io::{BufWriter, SeekFrom, Write};
use zip::ZipArchive;

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
            let (data_start, cipher_size) = (file.data_start(), file.compressed_size());
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

/// 读取一个包含密文/明文的文件
pub fn read_raw_file(path: &str, size: usize) -> Result<Vec<u8>, Error> {
    let mut file = File::open(path)?;
    let meta = metadata(path)?;
    Ok(file.read_exact(size.min(meta.len() as usize))?)
}

/// 读取一个包含密文/明文的 zip 文件的条目
pub fn read_zip_entry(path: &str, entry_name: &str, size: usize) -> Result<Vec<u8>, Error> {
    debug!("loading {}", path);
    let mut zip = ZipArchive::new(File::open(path)?)?;

    debug!("searching {}", entry_name);
    let zip_file = zip.by_name(entry_name)?;

    let data_start = zip_file.data_start();
    let real_size = zip_file.compressed_size() as usize;

    drop(zip_file);

    let mut reader = zip.into_inner();
    reader.seek(SeekFrom::Start(data_start))?;

    debug!("Found! size: {}", size);

    Ok(reader.read_exact(size.min(real_size))?)
}

pub fn open_output(path: &str) -> Result<impl Write, Error> {
    Ok(BufWriter::new(File::create(path)?))
}
