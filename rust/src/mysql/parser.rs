/* Copyright (C) 2022 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

// Author: Kotodian <blackfaceuncle@gmail.com>

//! MySQL nom parsers

use nom7::{
    branch::alt,
    bytes::streaming::{take, take_till},
    combinator::{cond, map, verify},
    multi::{fold_many1, many_m_n, many_till},
    number::streaming::{be_u16, be_u8, le_u16, le_u32},
    IResult,
};

fn read_uint(buf: &[u8], nbytes: usize) -> u64 {
    assert!((1..=8).contains(&nbytes) && nbytes <= buf.len());
    let mut out = 0u64;
    let ptr_out = &mut out as *mut u64 as *mut u8;
    unsafe {
        std::ptr::copy_nonoverlapping(buf.as_ptr(), ptr_out, nbytes);
    }

    out.to_le()
}

fn read_u24(buf: &[u8]) -> u32 {
    read_uint(buf, 3) as u32
}

#[derive(Debug)]
pub struct MysqlPacket {
    pub pkt_len: u32,
    pub pkt_num: u8,
}

#[derive(Debug)]
pub struct MysqlEofPacket {
    pub header: MysqlPacket,
    pub warnings: u16,
    pub status_flags: u16,
}

#[derive(Debug)]
pub enum MysqlCommand {
    Unknown,
    Quit,
    InitDb { schema: String },
    Query { query: String },
    FieldList { table: String },
}

#[derive(Debug)]
pub struct MysqlColumnDefinition {
    pub header: MysqlPacket,
    pub catalog: String,
    pub schema: String,
    pub table: String,
    pub orig_table: String,
    pub name: String,
    pub character_set: u16,
    pub column_length: u32,
    pub field_type: u8,
    pub flags: u16,
    pub decimals: u8,
}

#[derive(Debug)]
pub struct MysqlResultSetRow {
    pub header: MysqlPacket,
    pub text: Vec<String>,
}

#[derive(Debug)]
pub struct MysqlHandshakeRequest {
    pub header: MysqlPacket,
    pub protocol: u8,
    pub version: String,
    pub conn_id: u32,
    pub salt1: String,
    pub capability_flag1: u16,
    pub character_set: u8,
    pub status_flags: u16,
    pub capability_flags2: u16,
    pub auth_plugin_len: u8,
    pub salt2: String,
    pub auth_plugin_data: Option<String>,
}

#[derive(Debug)]
pub struct MysqlHandshakeResponse {
    pub header: MysqlPacket,
    pub capability_flags1: u16,
    pub capability_flags2: u16,
    pub max_packet_size: u32,
    pub character_set: u8,
    pub username: String,
    pub password: Vec<u8>,
}

#[derive(Debug)]
pub struct MysqlRequest {
    pub header: MysqlPacket,
    pub command_code: u8,
    pub command: MysqlCommand,
}

#[derive(Debug)]
pub enum MysqlResponsePacket {
    Unknown,
    Ok {
        header: MysqlPacket,
        rows: u8,
        flags: u16,
        warnings: u16,
    },
    FieldsList {
        columns: Vec<MysqlColumnDefinition>,
        eof: MysqlEofPacket,
    },
    ResultSet {
        header: MysqlPacket,
        n_cols: u8,
        columns: Vec<MysqlColumnDefinition>,
        eof: MysqlEofPacket,
        rows: Vec<MysqlResultSetRow>,
    },
}

#[derive(Debug)]
pub struct MysqlResponse {
    pub item: MysqlResponsePacket,
}

fn parse_packet_header(i: &[u8]) -> IResult<&[u8], MysqlPacket> {
    let (i, pkt_len) = map(take(3_u32), |len: &[u8]| read_u24(len))(i)?;
    let (i, pkt_num) = be_u8(i)?;
    Ok((i, MysqlPacket { pkt_len, pkt_num }))
}

fn parse_eof_packet(i: &[u8]) -> IResult<&[u8], MysqlEofPacket> {
    let (i, header) = parse_packet_header(i)?;
    let (i, _tag) = verify(be_u8, |&x| x == 0xfe)(i)?;
    let (i, warnings) = le_u16(i)?;
    let (i, status_flags) = le_u16(i)?;

    Ok((
        i,
        MysqlEofPacket {
            header,
            warnings,
            status_flags,
        },
    ))
}

fn parse_init_db_cmd(i: &[u8]) -> IResult<&[u8], MysqlCommand> {
    let schema = String::from_utf8(i.to_vec()).unwrap();
    Ok((&[][..], MysqlCommand::InitDb { schema }))
}

fn parse_query_cmd(i: &[u8]) -> IResult<&[u8], MysqlCommand> {
    let query = String::from_utf8(i.to_vec()).unwrap();
    Ok((&[][..], MysqlCommand::Query { query }))
}

fn parse_field_list_cmd(i: &[u8]) -> IResult<&[u8], MysqlCommand> {
    let (i, table) = map(take_till(|ch| ch == 0x00), |s: &[u8]| {
        String::from_utf8(s.to_vec()).unwrap()
    })(i)?;
    Ok((i, MysqlCommand::FieldList { table }))
}

fn parse_column_definition(i: &[u8]) -> IResult<&[u8], MysqlColumnDefinition> {
    let (i, header) = parse_packet_header(i)?;

    let (i, _len) = be_u8(i)?;
    let (i, catalog) = map(take(_len as u32), |s: &[u8]| {
        String::from_utf8(s.to_vec()).unwrap()
    })(i)?;

    let (i, _len) = be_u8(i)?;
    let (i, schema) = map(take(_len as u32), |s: &[u8]| {
        String::from_utf8(s.to_vec()).unwrap()
    })(i)?;

    let (i, _len) = be_u8(i)?;
    let (i, table) = map(take(_len as u32), |s: &[u8]| {
        String::from_utf8(s.to_vec()).unwrap()
    })(i)?;

    let (i, _len) = be_u8(i)?;
    let (i, orig_table) = map(take(_len as u32), |s: &[u8]| {
        String::from_utf8(s.to_vec()).unwrap()
    })(i)?;

    let (i, _len) = be_u8(i)?;
    let (i, name) = map(take(_len as u32), |s: &[u8]| {
        String::from_utf8(s.to_vec()).unwrap()
    })(i)?;

    let (i, _len) = be_u8(i)?;
    let (i, _orig_name) = map(take(_len as u32), |s: &[u8]| {
        String::from_utf8(s.to_vec()).unwrap()
    })(i)?;

    let (i, _) = take(1_u32)(i)?;
    let (i, character_set) = be_u16(i)?;
    let (i, column_length) = le_u32(i)?;
    let (i, field_type) = be_u8(i)?;
    let (i, flags) = be_u16(i)?;
    let (i, decimals) = be_u8(i)?;
    let (i, _filter) = take(2_u32)(i)?;
    let (i, len) = be_u8(i)?;
    let (i, _def_str) = cond(len != 0xfb, take(len))(i)?;

    Ok((
        i,
        MysqlColumnDefinition {
            header,
            catalog,
            schema,
            table,
            orig_table,
            name,
            character_set,
            column_length,
            field_type,
            flags,
            decimals,
        },
    ))
}

fn parse_column_definition2(i: &[u8]) -> IResult<&[u8], MysqlColumnDefinition> {
    let (i, header) = parse_packet_header(i)?;

    let (i, _len) = be_u8(i)?;
    let (i, _catalog) = map(take(_len as u32), |s: &[u8]| {
        String::from_utf8(s.to_vec()).unwrap()
    })(i)?;

    let (i, _len) = be_u8(i)?;
    let (i, schema) = map(take(_len as u32), |s: &[u8]| {
        String::from_utf8(s.to_vec()).unwrap()
    })(i)?;

    let (i, _len) = be_u8(i)?;
    let (i, table) = map(take(_len as u32), |s: &[u8]| {
        String::from_utf8(s.to_vec()).unwrap()
    })(i)?;

    let (i, _len) = be_u8(i)?;
    let (i, orig_table) = map(take(_len as u32), |s: &[u8]| {
        String::from_utf8(s.to_vec()).unwrap()
    })(i)?;

    let (i, _len) = be_u8(i)?;
    let (i, name) = map(take(_len as u32), |s: &[u8]| {
        String::from_utf8(s.to_vec()).unwrap()
    })(i)?;

    let (i, _len) = be_u8(i)?;
    let (i, _orig_name) = map(take(_len as u32), |s: &[u8]| {
        String::from_utf8(s.to_vec()).unwrap()
    })(i)?;

    let (i, _) = take(1_u32)(i)?;
    let (i, character_set) = be_u16(i)?;
    let (i, column_length) = le_u32(i)?;
    let (i, field_type) = be_u8(i)?;
    let (i, flags) = be_u16(i)?;
    let (i, decimals) = be_u8(i)?;
    let (i, _filter) = take(2_u32)(i)?;
    let (i, len) = be_u8(i)?;
    let (i, _def_str) = cond(len != 0xfb, take(len))(i)?;

    Ok((
        i,
        MysqlColumnDefinition {
            header,
            catalog: "def".to_string(),
            schema,
            table,
            orig_table,
            name,
            character_set,
            column_length,
            field_type,
            flags,
            decimals,
        },
    ))
}

fn parse_response_field_list(i: &[u8]) -> IResult<&[u8], MysqlResponse> {
    let (i, fields) = many_till(parse_column_definition, parse_eof_packet)(i)?;
    Ok((
        i,
        MysqlResponse {
            item: MysqlResponsePacket::FieldsList {
                columns: fields.0,
                eof: fields.1,
            },
        },
    ))
}

fn parse_resultset_row(n_cols: u8) -> impl FnMut(&[u8]) -> IResult<&[u8], MysqlResultSetRow>
where
{
    move |i| -> IResult<&[u8], MysqlResultSetRow> {
        let (i, header) = parse_packet_header(i)?;
        let (i, _len) = be_u8(i)?;
        let (i, text) = many_m_n(1, n_cols as usize, |i| -> IResult<&[u8], String> {
            let (i, len) = be_u8(i)?;
            let (i, text) = map(take(len as u32), |s: &[u8]| {
                String::from_utf8(s.to_vec()).unwrap()
            })(i)?;
            Ok((i, text))
        })(i)?;
        Ok((i, MysqlResultSetRow { header, text }))
    }
}

fn parse_response_resultset(i: &[u8]) -> IResult<&[u8], MysqlResponse> {
    let (i, header) = parse_packet_header(i)?;
    let (i, n_cols) = be_u8(i)?;
    let (i, columns) = many_m_n(1, n_cols as usize, parse_column_definition2)(i)?;
    let (i, eof) = parse_eof_packet(i)?;
    let (i, rows) = fold_many1(
        parse_resultset_row(n_cols),
        Vec::new,
        |mut rows: Vec<_>, r| {
            rows.push(r);
            rows
        },
    )(i)?;
    Ok((
        i,
        MysqlResponse {
            item: MysqlResponsePacket::ResultSet {
                header,
                n_cols,
                columns,
                eof,
                rows,
            },
        },
    ))
}

fn parse_response_ok(i: &[u8]) -> IResult<&[u8], MysqlResponse> {
    let (i, header) = parse_packet_header(i)?;
    let (i, _code) = verify(be_u8, |&x| x == 0x00_u8)(i)?;
    let (i, rows) = be_u8(i)?;
    let (i, flags) = le_u16(i)?;
    let (i, warnings) = le_u16(i)?;
    Ok((
        i,
        MysqlResponse {
            item: MysqlResponsePacket::Ok {
                header,
                rows,
                flags,
                warnings,
            },
        },
    ))
}

pub fn parse_handshake_request(i: &[u8]) -> IResult<&[u8], MysqlHandshakeRequest> {
    let (i, header) = parse_packet_header(i)?;
    let (i, protocol) = verify(be_u8, |&x| x == 0x0a_u8)(i)?;
    let (i, version) = map(take_till(|ch| ch == 0x00), |s: &[u8]| {
        String::from_utf8(s.to_vec()).unwrap()
    })(i)?;
    let (i, _) = take(1_u32)(i)?;
    let (i, conn_id) = le_u32(i)?;
    let (i, salt1) = map(take(8_u32), |s: &[u8]| {
        String::from_utf8(s.to_vec()).unwrap()
    })(i)?;
    let (i, _) = take(1_u32)(i)?;
    let (i, capability_flag1) = le_u16(i)?;
    let (i, character_set) = be_u8(i)?;
    let (i, status_flags) = le_u16(i)?;
    let (i, capability_flags2) = be_u16(i)?;
    let (i, auth_plugin_len) = be_u8(i)?;
    let (i, _) = take(10_u32)(i)?;
    let (i, salt2) = map(take_till(|ch| ch == 0x00), |s: &[u8]| {
        String::from_utf8(s.to_vec()).unwrap()
    })(i)?;
    let (i, auth_plugin_data) = cond(
        auth_plugin_len > 0,
        map(take_till(|ch| ch == 0x00), |s: &[u8]| {
            String::from_utf8(s.to_vec()).unwrap()
        }),
    )(i)?;
    Ok((
        i,
        MysqlHandshakeRequest {
            header,
            protocol,
            version,
            conn_id,
            salt1,
            capability_flag1,
            character_set,
            status_flags,
            capability_flags2,
            auth_plugin_len,
            salt2,
            auth_plugin_data,
        },
    ))
}

pub fn parse_handshake_response(i: &[u8]) -> IResult<&[u8], MysqlHandshakeResponse> {
    let (i, header) = parse_packet_header(i)?;
    let (i, capability_flags1) = le_u16(i)?;
    let (i, capability_flags2) = le_u16(i)?;
    let (i, max_packet_size) = le_u32(i)?;
    let (i, character_set) = be_u8(i)?;
    let (i, _) = take(23_u32)(i)?;
    let (i, username) = map(take_till(|ch| ch == 0x00), |s: &[u8]| {
        String::from_utf8(s.to_vec()).unwrap()
    })(i)?;
    let (i, _) = take(1_u32)(i)?;
    let (i, len) = be_u8(i)?;
    let (i, password) = map(take(20_u32), |s: &[u8]| s.to_vec())(i)?;
    Ok((
        i,
        MysqlHandshakeResponse {
            header,
            capability_flags1,
            capability_flags2,
            max_packet_size,
            character_set,
            username,
            password,
        },
    ))
}

pub fn parse_request(i: &[u8]) -> IResult<&[u8], MysqlRequest> {
    let (i, header) = parse_packet_header(i)?;
    let (i, command_code) = be_u8(i)?;
    match command_code {
        0x01 => Ok((
            i,
            MysqlRequest {
                header,
                command_code,
                command: MysqlCommand::Quit,
            },
        )),

        0x02 => {
            let (i, command) = parse_init_db_cmd(i)?;
            Ok((
                i,
                MysqlRequest {
                    header,
                    command_code,
                    command,
                },
            ))
        }

        0x03 => {
            let (i, command) = parse_query_cmd(i)?;
            Ok((
                i,
                MysqlRequest {
                    header,
                    command_code,
                    command,
                },
            ))
        }

        0x04 => {
            let (i, command) = parse_field_list_cmd(i)?;
            Ok((
                i,
                MysqlRequest {
                    header,
                    command_code,
                    command,
                },
            ))
        }

        _ => Ok((
            i,
            MysqlRequest {
                header,
                command_code,
                command: MysqlCommand::Unknown,
            },
        )),
    }
}

pub fn parse_response(i: &[u8]) -> IResult<&[u8], MysqlResponse> {
    let (i, _header) = parse_packet_header(i)?;
    let (i, response_code) = be_u8(i)?;
    match response_code {
        3 => alt((parse_response_ok, parse_response_resultset))(i),
        4 => alt((parse_response_ok, parse_response_field_list))(i),
        _ => Ok((
            i,
            MysqlResponse {
                item: MysqlResponsePacket::Unknown,
            },
        )),
    }
}
