<?php
declare(strict_types=1);
if (!defined('BASE_URL')) { http_response_code(404); exit; }
function roleInputs(array $roles,bool $adminAllowed): void {
    echo '<fieldset class="roles"><legend>'.tr_html('Library roles').'</legend>';
    foreach (LIBRARY_ROLE_LABELS as $key=>$label) {
        if (!$adminAllowed && $key==='admin') continue;
        echo '<label><input type="checkbox" name="roles[]" value="'.h($key).'"'.(in_array($key,$roles,true)?' checked':'').'>'.tr_html($label).'</label>';
    }
    echo '</fieldset>';
}
$owner=$library['owner']===$viewer;
?>
<?php if (isset($permissions['agent_upload'])): ?>
<dialog id="tools-dialog" class="sheet" aria-labelledby="tools-title">
<div class="bar dialog-head"><h2 id="tools-title"><?=tr_html('CLI / API & upload Skill')?></h2><button type="button" class="icon-button dialog-close" aria-label="<?=tr_html('Close')?>"><?=icon('close')?></button></div>
<p class="muted"><?=tr_html('Copy once and paste into your agent. The instruction includes an upload-only token for the selected folder, valid for 90 days.')?></p>
<form method="post" action="up.php" id="agent-setup">
<?php hidden($csrf,'agent_setup',$dir); ?>
<label><?=tr_html('Upload destination')?><select name="destination">
<?php foreach (['',...$directories] as $destination): ?><option value="<?=h($destination)?>" <?=$destination===$dir?'selected':''?>><?=h($destination===''?tr('Library root'):$destination)?></option><?php endforeach; ?>
</select></label>
<details class="tool-divider"><summary><?=tr_html('Token options')?></summary>
<label><?=tr_html('Token label')?><input name="name" maxlength="80"></label>
<label><?=tr_html('Validity in days')?><input name="days" type="number" value="90" min="1" max="365" required></label>
<?php if (isset($permissions['tokens'])): ?>
<label><?=tr_html('Upload scope')?><select name="scope"><option value="folder"><?=tr_html('Selected folder only')?></option><option value="library"><?=tr_html('Entire library')?></option></select></label>
<label><input type="checkbox" name="mkdir" value="1"> <?=tr_html('Allow folder creation with an entire-library token')?></label>
<?php endif; ?></details>
<button class="primary" data-copied="<?=tr_html('Copied. Paste it into your agent.')?>" data-fallback="<?=tr_html('Copy failed. Select and copy the instructions below.')?>" data-failed="<?=tr_html('Could not prepare the installation instructions. Try again.')?>"><?=tr_html('Copy Agent setup instructions')?></button>
</form>
<p id="agent-setup-status" role="status"></p>
<textarea hidden readonly id="agent-setup-text" aria-label="<?=tr_html('Agent setup instructions')?>" lang="en"></textarea>
<div class="tool-divider">
<h3><?=tr_html('Active upload tokens')?></h3>
<?php if ($owner && $library['legacy']===$viewer && isset($user['token'])): ?>
<div class="token-row bar"><span><?=tr_html('Legacy personal upload token')?></span>
<form method="post" action="up.php" data-confirm="<?=tr_html('Revoke this token? Existing scripts using it will stop working.')?>"><?php hidden($csrf,'legacy_token_revoke',$dir);?><button class="danger"><?=tr_html('Revoke')?></button></form></div>
<?php endif; ?>
<?php foreach ($library['tokens'] as $id=>$item): if ($item['user']!==$viewer || !empty($item['revoked']) || $item['expires']<=time()) continue; ?>
<div class="token-row bar"><span><?=h(($item['name']??'')!==''?$item['name'].' · ':'')?><?=h(!empty($item['whole'])?tr('Entire library'):($item['dir']?:tr('Library root')))?> · <?=h(sprintf(tr('Expires %s UTC'),gmdate('Y-m-d',$item['expires'])))?> <small>· <?=h(substr($id,0,8))?></small></span>
<form method="post" action="up.php"><?php hidden($csrf,'agent_revoke',$dir);?><input type="hidden" name="token_id" value="<?=h($id)?>"><button class="danger"><?=tr_html('Revoke')?></button></form></div>
<?php endforeach; ?>
<a class="button" href="<?=h(libraryHref($dir,['skill'=>'1']))?>"><?=icon('download')?><?=tr_html('Download SKILL.md')?></a>
</div></dialog>
<?php endif; ?>
<?php if (isset($permissions['members'])): ?>
<dialog id="members-dialog" class="sheet" aria-labelledby="members-title">
<div class="bar dialog-head"><h2 id="members-title"><?=tr_html('Members and permissions')?></h2><button type="button" class="icon-button dialog-close" aria-label="<?=tr_html('Close')?>"><?=icon('close')?></button></div>
<p class="muted"><?=tr_html('Roles apply only to this library. Web upload and Agent upload are separate.')?></p>
<div class="member-row"><strong><?=h($library['owner'])?></strong> · <?=tr_html('Owner')?></div>
<?php foreach ($library['members'] as $member=>$roles): $member=(string)$member; $editable=$member!==$viewer && ($owner||!in_array('admin',$roles,true)); ?>
<details class="member-row"><summary><?=h($member)?> · <?=h(implode(' · ',array_map(static fn($r)=>tr(LIBRARY_ROLE_LABELS[$r]),$roles)))?></summary>
<?php if ($editable): ?>
<form method="post" action="up.php"><?php hidden($csrf,'member_save',$dir);?><input type="hidden" name="member" value="<?=h($member)?>"><?php roleInputs($roles,$owner);?><button class="primary"><?=tr_html('Save permissions')?></button></form>
<form method="post" action="up.php" data-confirm="<?=tr_html('Remove access for this member?')?>"><?php hidden($csrf,'member_remove',$dir);?><input type="hidden" name="member" value="<?=h($member)?>"><button class="danger"><?=tr_html('Remove access')?></button></form>
<?php endif; ?></details>
<?php endforeach; ?>
<?php foreach ($library['invites']??[] as $member=>$invite): if ($invite['expires']<=time()) continue; ?>
<div class="member-row bar"><span><?=h((string)$member)?> · <?=tr_html('Invitation pending')?></span>
<?php if ($owner||!in_array('admin',$invite['roles'],true)): ?><form method="post" action="up.php"><?php hidden($csrf,'member_remove',$dir);?><input type="hidden" name="member" value="<?=h((string)$member)?>"><button><?=tr_html('Cancel invitation')?></button></form><?php endif; ?></div>
<?php endforeach; ?>
<div class="tool-divider"><h3><?=tr_html('Invite an existing account')?></h3><form method="post" action="up.php"><?php hidden($csrf,'member_save',$dir);?>
<label><?=tr_html('Username')?><input name="member" maxlength="32" required autocapitalize="none"></label><?php roleInputs([],$owner);?><button class="primary"><?=tr_html('Send invitation')?></button></form></div>
<?php if ($owner): ?>
<details class="tool-divider"><summary><?=tr_html('Library settings')?></summary>
<form method="post" action="up.php"><?php hidden($csrf,'library_rename',$dir);?><label><?=tr_html('Library name')?><input name="title" value="<?=h(libraryTitle($library,$viewer))?>" required maxlength="120"></label><button><?=tr_html('Save name')?></button></form>
<form method="post" action="up.php" data-confirm="<?=tr_html('Archive this library? Its upload tokens and anonymous shares will stop working, even after restore.')?>"><?php hidden($csrf,'library_archive',$dir);?><button class="danger"><?=tr_html('Archive library')?></button></form>
</details><?php endif; ?>
<?php if ($owner && $library['members']): ?>
<details class="tool-divider"><summary><?=tr_html('Transfer ownership')?></summary>
<?php if (($library['transfer']['expires']??0)>time()): ?>
<p><?=h(sprintf(tr('Waiting for %s to accept ownership.'),$library['transfer']['to']))?></p>
<form method="post" action="up.php"><?php hidden($csrf,'transfer_cancel',$dir);?><button><?=tr_html('Cancel')?></button></form>
<?php else: ?>
<form method="post" action="up.php" data-confirm="<?=tr_html('You will lose access when the new owner accepts. Continue?')?>"><?php hidden($csrf,'transfer_begin',$dir);?>
<label><?=tr_html('Username')?><select name="member" required>
<?php foreach ($library['members'] as $member=>$roles): if (!in_array('view',libraryPermissions($library,(string)$member),true)) continue; ?>
<option value="<?=h((string)$member)?>"><?=h((string)$member)?></option><?php endforeach; ?></select></label>
<button><?=tr_html('Request transfer')?></button></form>
<?php endif; ?></details>
<?php endif; ?>
<?php if (isset($permissions['tokens'])): ?>
<details class="tool-divider"><summary><?=tr_html('Manage member upload tokens')?></summary>
<?php foreach ($library['tokens'] as $id=>$item): if (!empty($item['revoked']) || $item['expires']<=time()) continue; ?>
<div class="token-row bar"><span><?=h($item['user'])?> · <?=h(($item['name']??'')!==''?$item['name'].' · ':'')?><?=h(!empty($item['whole'])?tr('Entire library'):($item['dir']?:tr('Library root')))?> · <?=h(substr($id,0,8))?></span>
<form method="post" action="up.php"><?php hidden($csrf,'managed_token_revoke',$dir);?><input type="hidden" name="token_id" value="<?=h($id)?>"><button class="danger"><?=tr_html('Revoke')?></button></form></div>
<?php endforeach; ?>
</details><?php endif; ?>
</dialog>
<?php endif; ?>
