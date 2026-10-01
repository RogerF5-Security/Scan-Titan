local smb = require "smb"
local stdnse = require "stdnse"

description = [[Scan Titan: bounded SMBv1 null/Guest login and directory listing.
Does not create, modify, delete or read file contents. No brute force.]]
author = "Scan Titan"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

hostrule = function(host) return smb.get_port(host) ~= nil end

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
          local connected, tree = smb.start_ex(host, true, true, share, nil, nil, overrides)
          if not connected then
            access.list_root = "false"
            access.error = tostring(tree)
          else
            local names = {}
            local ok, err = pcall(function()
              for entry in smb.find_files(tree, "\\*", {maxfiles=5}) do
                table.insert(names, entry.fname)
                if #names >= 5 then break end
              end
            end)
            -- Nmap's iterator hides listing errors; demand at least one returned entry.
            access.list_root = tostring(ok and #names > 0)
            access.entries_observed = #names
            access.entries = names
            if not ok then access.error = tostring(err) end
            smb.stop(tree)
          end
        end
      end
    end
  end
  return output
end
