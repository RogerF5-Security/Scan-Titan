local smb = require "smb"
local stdnse = require "stdnse"

description = [[Scan Titan: bounded SMBv1 null/Guest login and directory listing.
Does not create, modify, delete or read file contents. No brute force.]]
author = "Scan Titan"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

hostrule = function(host) return smb.get_port(host) ~= nil end

-- SMB FIND_FIRST2, bounded to five entries and closed by the server immediately.
-- Parse explicit lengths: some servers do not NUL-terminate returned filenames,
-- which Nmap's find_files iterator assumes. No file contents are requested.
local function list_root(state)
  local search = string.pack("<I2I2I2I2I4z", 0x37, 5, 0x05, 0x104, 0, "\\*")
  local params = string.pack("<I2I2I2I2BBI2I4I2I2I2I2I2BBI2",
    #search, 0, 10, 16384, 0, 0, 0, 5000, 0, #search, 68, 0, 0, 1, 0, 1)
  local sent, err = smb.smb_send(state, smb.smb_encode_header(state, 0x32), params, "\0\0\0" .. search)
  if not sent then return false, tostring(err) end
  local ok, header, words, bytes = smb.smb_read(state)
  if not ok then return false, tostring(header) end
  if #header < 32 or #words < 20 then return false, "Truncated SMB response" end
  local status = string.unpack("<I4", header, 6)
  if status ~= 0 then return false, string.format("SMB status 0x%08x", status) end
  local total_params, total_data, _, pcount, poffset, pdisp, dcount, doffset, ddisp =
    string.unpack("<I2I2I2I2I2I2I2I2I2", words)
  local base = 35 + #words
  local pstart, dstart = poffset - base + 1, doffset - base + 1
  if pdisp ~= 0 or ddisp ~= 0 or total_params ~= pcount or total_data ~= dcount then
    return false, "Fragmented directory response; coverage incomplete"
  end
  if pcount < 10 or pstart < 1 or pstart + pcount - 1 > #bytes then
    return false, "Truncated directory parameters"
  end
  local _, count = string.unpack("<I2I2", bytes, pstart)
  if count == 0 then return true, 0 end
  if count > 5 or dstart < 1 or dstart + dcount - 1 > #bytes then
    return false, "Invalid directory data bounds"
  end
  local data = bytes:sub(dstart, dstart + dcount - 1)
  local cursor = 1
  for index = 1, count do
    if cursor + 93 > #data then return false, "Truncated directory entry" end
    local next_offset = string.unpack("<I4", data, cursor)
    local name_length = string.unpack("<I4", data, cursor + 60)
    if name_length < 1 or cursor + 93 + name_length > #data then
      return false, "Truncated directory filename"
    end
    if index < count then
      if next_offset < 94 + name_length then return false, "Invalid next entry offset" end
      cursor = cursor + next_offset
    end
  end
  return true, count
end

action = function(host)
  local shares = stdnse.get_script_args("titan-smb-access.shares") or {"SharedDocs", "Public", "Users", "C$", "ADMIN$"}
  if type(shares) == "string" then shares = {shares} end
  local output = stdnse.output_table()
  output.dialect = "SMBv1 check only"
  for _, user in ipairs({"", "Guest"}) do
    local label = user == "" and "null" or "Guest/empty-password"
    local result = stdnse.output_table()
    output[label] = result
    local overrides = user == "" and smb.get_overrides_anonymous() or smb.get_overrides(user, "", "", nil, "ntlm")
    local status, state = smb.start_ex(host, true, true, nil, nil, nil, overrides)
    if not status then
      result.accepted = "false"
      result.error = tostring(state)
    else
      result.accepted = "true"
      result.guest_mapping = tostring(state.is_guest == 1)
      result.os = tostring(state.os or "")
      result.server = tostring(state.server or "")
      smb.stop(state)
      for index, share in ipairs(shares) do
        if index > 8 then break end
        if share ~= "IPC$" then
          local access = stdnse.output_table()
          result[share] = access
          local unc = "\\\\" .. host.ip .. "\\" .. share:upper()
          local connected, tree = smb.start_ex(host, true, true, unc, nil, nil, overrides)
          if not connected then
            access.list_root = "false"
            access.error = tostring(tree)
          else
            local ran, listed, count = pcall(list_root, tree)
            access.list_root = tostring(ran and listed == true)
            access.entries_observed = ran and listed and count or 0
            if not ran or not listed then access.error = tostring(ran and count or listed) end
            smb.stop(tree)
          end
        end
      end
    end
  end
  return output
end
