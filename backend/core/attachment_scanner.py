"""Safe attachment inspection: metadata, archive listing, optional YARA/ClamAV. Never executes payloads."""
from __future__ import annotations
import io, os, shutil, subprocess, tempfile, zipfile
from pathlib import Path

def inspect_attachment(data:bytes, filename:str, rules_path:Path|None=None) -> dict:
    result={'archive':False,'archive_entries':[],'archive_warning':None,'yara':{'status':'not_installed'},'clamav':{'status':'not_installed'},'qr_codes':[]}
    if data.startswith(b'PK\x03\x04'):
        result['archive']=True
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                infos=z.infolist()[:100]
                result['archive_entries']=[{'name':Path(i.filename).name[:160],'size':i.file_size,'compressed_size':i.compress_size,'encrypted':bool(i.flag_bits&1)} for i in infos]
                suspicious=[i.filename for i in infos if Path(i.filename).suffix.lower() in {'.exe','.js','.vbs','.ps1','.hta','.lnk','.scr','.docm','.xlsm'}]
                if suspicious: result['archive_warning']='Archive contains potentially risky file types: '+', '.join(Path(x).name for x in suspicious[:10])
                if any(i.file_size>50*1024*1024 for i in infos): result['archive_warning']='Archive contains an entry larger than 50 MiB; contents were not extracted.'
        except zipfile.BadZipFile: result['archive_warning']='ZIP signature detected but archive structure is invalid.'
    try:
        from PIL import Image
        from pyzbar.pyzbar import decode
        if data.startswith((b'\x89PNG',b'GIF8',b'\xff\xd8')):
            result['qr_codes']=[x.data.decode('utf-8','replace')[:2048] for x in decode(Image.open(io.BytesIO(data))) if x.data]
    except ImportError: pass
    except Exception: pass
    try:
        import yara
        if rules_path and Path(rules_path).exists():
            rules=yara.compile(filepath=str(rules_path)); matches=rules.match(data=data,timeout=2)
            result['yara']={'status':'complete','matches':[m.rule for m in matches]}
        else: result['yara']={'status':'not_configured'}
    except ImportError: result['yara']={'status':'not_installed'}
    except Exception as e: result['yara']={'status':'error','message':str(e)[:240]}
    clamscan=shutil.which('clamscan')
    if clamscan:
        tmp=None
        try:
            with tempfile.NamedTemporaryFile(prefix='pgscan_',suffix=Path(filename).suffix,delete=False) as f: f.write(data); tmp=f.name
            proc=subprocess.run([clamscan,'--no-summary',tmp],capture_output=True,text=True,timeout=20,check=False)
            output=(proc.stdout or proc.stderr).strip()
            result['clamav']={'status':'complete','infected':proc.returncode==1,'exit_code':proc.returncode,'output':output[-500:]}
        except subprocess.TimeoutExpired: result['clamav']={'status':'timeout'}
        except Exception as e: result['clamav']={'status':'error','message':str(e)[:240]}
        finally:
            if tmp and os.path.exists(tmp): os.unlink(tmp)
    return result
