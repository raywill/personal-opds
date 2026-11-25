<?php
declare(strict_types=1);
if (!defined('BASE_URL')) { http_response_code(404); exit; }
function roleInputs(string $selected,bool $adminAllowed): void { ?>
<fieldset class="role-options"><legend><?=tr_html('Choose one role')?></legend>
<?php foreach (LIBRARY_ROLE_GROUPS as $group=>$roles): ?>
<div class="role-group"><h3><?=tr_html($group)?></h3>
<div class="role-grid">
<?php foreach ($roles as $role): if (!$adminAllowed&&$role==='admin') continue; ?>
<label class="role-card"><input type="radio" name="role" value="<?=h($role)?>" <?=$selected===$role?'checked':''?> required>
<span><strong><?=h(libraryRoleLabel($role))?></strong><small><?=tr_html(LIBRARY_ROLE_DESCRIPTIONS[$role])?></small></span></label>
<?php endforeach; ?></div></div>
<?php endforeach; ?></fieldset>
<?php }
function memberAvatar(string $username): void { ?><span class="member-avatar" aria-hidden="true"><?=h(strtoupper(substr($username,0,1)))?></span><?php }
$owner=$library['owner']===$viewer;
?>
<?php if (isset($permissions['agent_upload'])): ?>
<dialog id="tools-dialog" class="sheet" aria-labelledby="tools-title">
<div class="bar dialog-head"><h2 id="tools-title"><?=tr_html('Connect upload tools')?></h2><button type="button" class="icon-button dialog-close" aria-label="<?=tr_html('Close')?>"><?=icon('close')?></button></div>
<section class="tool-divider"><h3><?=tr_html('One-click Agent setup')?></h3>
<p class="muted"><?=tr_html('Copy once and paste into your agent. The instruction includes an upload-only token for the selected folder, valid for 90 days.')?></p>
<form method="post" action="up.php" id="agent-setup">
<?php hidden($csrf,'agent_setup',$dir); ?>
<label><?=tr_html('Upload destination')?><select name="destination">
<?php foreach (['',...$directories] as $destination): ?><option value="<?=h($destination)?>" <?=$destination===$dir?'selected':''?>><?=h($destination===''?$libraryName:$destination)?></option><?php endforeach; ?>
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
<textarea hidden readonly id="agent-setup-text" aria-label="<?=tr_html('Agent setup instructions')?>" lang="en"></textarea></section>
<details class="tool-divider"><summary><?=tr_html('Terminal command')?></summary>
<p class="muted"><?=tr_html('Set OPDS_TOKEN to your upload token, then run this command with your file.')?></p>
<pre><?=h("curl --fail-with-body -H \"Authorization: Bearer \$OPDS_TOKEN\" -F 'files[]=@./book.epub' -- ".escapeshellarg(PUBLIC_UPLOAD_URL))?></pre>
</details>
<details class="tool-divider"><summary><?=tr_html('API endpoint')?></summary>
<p class="muted"><?=tr_html('Use your upload token as an Authorization: Bearer header. Upload with multipart POST and the files[] field.')?></p>
<label><?=tr_html('Upload API URL')?><input class="share-link" readonly value="<?=h(PUBLIC_UPLOAD_URL)?>"></label>
</details>
<div class="tool-divider">
<h3><?=tr_html('Active upload tokens')?></h3>
<?php if ($owner && $library['legacy']===$viewer && isset($user['token'])): ?>
<div class="token-row bar"><span><?=tr_html('Legacy personal upload token')?></span>
<form method="post" action="up.php" data-confirm="<?=tr_html('Revoke this token? Existing scripts using it will stop working.')?>"><?php hidden($csrf,'legacy_token_revoke',$dir);?><button class="danger"><?=tr_html('Revoke')?></button></form></div>
<?php endif; ?>
<?php foreach ($library['tokens'] as $id=>$item): if ($item['user']!==$viewer || !empty($item['revoked']) || $item['expires']<=time()) continue; ?>
<div class="token-row bar"><span><?=h(($item['name']??'')!==''?$item['name'].' · ':'')?><?=h(!empty($item['whole'])?tr('Entire library'):($item['dir']?:$libraryName))?> · <?=h(sprintf(tr('Expires %s UTC'),gmdate('Y-m-d',$item['expires'])))?> <small>· <?=h(substr($id,0,8))?></small></span>
<form method="post" action="up.php"><?php hidden($csrf,'agent_revoke',$dir);?><input type="hidden" name="token_id" value="<?=h($id)?>"><button class="danger"><?=tr_html('Revoke')?></button></form></div>
<?php endforeach; ?>
<a class="button" href="<?=h(libraryHref($dir,['skill'=>'1']))?>"><?=icon('download')?><?=tr_html('Download SKILL.md')?></a>
</div>
<?php if (isset($permissions['tokens'])): ?>
<details class="tool-divider"><summary><?=tr_html('Library members’ upload tokens')?></summary>
<?php foreach ($library['tokens'] as $id=>$item): if ($item['user']===$viewer || !empty($item['revoked']) || $item['expires']<=time()) continue; ?>
<div class="token-row bar"><span><?=h($item['user'])?> · <?=h(($item['name']??'')!==''?$item['name'].' · ':'')?><?=h(!empty($item['whole'])?tr('Entire library'):($item['dir']?:$libraryName))?> · <?=h(substr($id,0,8))?></span>
<form method="post" action="up.php"><?php hidden($csrf,'managed_token_revoke',$dir);?><input type="hidden" name="token_id" value="<?=h($id)?>"><button class="danger"><?=tr_html('Revoke')?></button></form></div>
<?php endforeach; ?>
</details><?php endif; ?>

</dialog>
<?php endif; ?>
<?php if ($owner): ?>
<dialog id="library-settings-dialog" class="sheet manage-dialog" aria-labelledby="settings-title">
<div class="bar dialog-head"><h2 id="settings-title"><?=tr_html('Library settings')?></h2><button type="button" class="icon-button dialog-close" aria-label="<?=tr_html('Close')?>"><?=icon('close')?></button></div>
<p class="muted"><?=h(libraryTitle($library,$viewer))?></p>
<section class="settings-section"><h3><?=tr_html('General')?></h3>
<form method="post" action="up.php"><?php hidden($csrf,'library_rename',$dir);?><label><?=tr_html('Library name')?><input name="title" value="<?=h(libraryTitle($library,$viewer))?>" required maxlength="120"></label><button><?=tr_html('Save name')?></button></form>
</section>

<section class="settings-section archive-section"><h3><?=tr_html('Archive library')?></h3><p class="muted"><?=tr_html('Keeps books and members, but disables access and revokes links and tokens.')?></p>
<form method="post" action="up.php" data-confirm="<?=tr_html('Archive this library? Its upload tokens and anonymous shares will stop working, even after restore.')?>"><?php hidden($csrf,'library_archive',$dir);?><button class="danger"><?=tr_html('Archive library')?></button></form>
</section></dialog>
<?php endif; ?>
<?php if (isset($permissions['members'])):
$invitations=libraryInvitationRows($library);
$pendingCount=count(array_filter($invitations,static fn($invite)=>$invite['status']==='pending'));
$newInviteId=($createdInvitation['library']??null)===$library['id']?($createdInvitation['id']??''):'';
$tabPending=($_GET['manage']??'')==='pending'||($error!==''&&$action==='member_cancel');
$inviteError=$error!==''&&$action==='member_invite';
$editError=$error!==''&&$action==='member_edit';
$manageOpen=!$inviteError&&!$editError&&(in_array($_GET['manage']??null,['members','pending'],true)||($error!==''&&in_array($action,['member_remove','member_cancel'],true)));
$draftMember=is_string($_POST['member']??null)?$_POST['member']:'';
$draftRole=is_string($_POST['role']??null)?$_POST['role']:'';
?>
<dialog id="members-dialog" class="sheet manage-dialog" aria-labelledby="members-title" <?=$manageOpen?'data-manage-open':''?>>
<div class="bar dialog-head"><div><p class="eyebrow"><?=h(libraryTitle($library,$viewer))?></p><h2 id="members-title"><?=tr_html('Library members')?></h2></div><button type="button" class="icon-button dialog-close" aria-label="<?=tr_html('Close')?>"><?=icon('close')?></button></div>
<?php if ($manageOpen&&($notice!==''||$error!=='')): ?><p class="<?=$error!==''?'error':'status'?>" role="<?=$error!==''?'alert':'status'?>"><?=h($error!==''?$error:$notice)?></p><?php endif; ?>
<div class="member-toolbar">
<div role="tablist" aria-label="<?=tr_html('Membership views')?>" class="member-tabs">
<button type="button" id="member-tab-current" role="tab" aria-controls="member-current" aria-selected="<?=$tabPending?'false':'true'?>" tabindex="<?=$tabPending?-1:0?>"><?=tr_html('Members')?> <span id="member-count"><?=count($library['members'])+1?></span></button>
<button type="button" id="member-tab-pending" role="tab" aria-controls="member-pending" aria-selected="<?=$tabPending?'true':'false'?>" tabindex="<?=$tabPending?0:-1?>"><?=tr_html('Invitation history')?> <span id="pending-count" title="<?=tr_html('Pending invitations')?>"><?=$pendingCount?></span></button>
</div>
<button type="button" class="primary" data-dialog="invite-member-dialog"><?=icon('plus')?><?=tr_html('Invite member')?></button>
</div>
<div id="member-current" role="tabpanel" aria-labelledby="member-tab-current" tabindex="0" <?=$tabPending?'hidden':''?>>
<div class="member-line"><?php memberAvatar($library['owner']);?><strong><?=h($library['owner'])?></strong><span class="role-chip role-owner"><?=tr_html('Owner')?></span></div>
<?php foreach ($library['members'] as $member=>$role): $member=(string)$member; ?>
<div class="member-line"><?php memberAvatar($member);?><strong><?=h($member)?></strong><span class="role-chip"><?=h(libraryRoleLabel($role))?></span>
<?php if ($member!==$viewer&&($owner||$role!=='admin')): ?>
<details class="book-menu member-menu"><summary class="button icon-button" aria-label="<?=h(sprintf(tr('Actions for %s'),$member))?>"><?=icon('more')?></summary>
<div class="book-actions">
<button type="button" data-dialog="edit-role-dialog" data-member="<?=h($member)?>" data-member-role="<?=h(is_string($role)?$role:'')?>"><?=tr_html('Change role')?></button>
<form method="post" action="up.php" data-confirm="<?=tr_html('Remove this member from this library? Their account and own library will stay active.')?>"><?php hidden($csrf,'member_remove',$dir);?><input type="hidden" name="member" value="<?=h($member)?>"><button class="danger"><?=tr_html('Remove from library')?></button></form>
</div></details>
<?php endif; ?></div>
<?php endforeach; ?></div>
<div id="member-pending" role="tabpanel" aria-labelledby="member-tab-pending" tabindex="0" <?=$tabPending?'':'hidden'?>>
<div class="invitation-toolbar"><h3><?=tr_html('Invitation status')?></h3><button type="button" id="refresh-invitations" class="icon-button" aria-label="<?=tr_html('Refresh invitation status')?>" title="<?=tr_html('Refresh invitation status')?>" data-url="<?=h(libraryHref($dir,['manage'=>'pending']))?>" data-done="<?=tr_html('Invitation status updated.')?>" data-error="<?=tr_html('Could not refresh invitations. Try again.')?>"><?=icon('refresh')?></button></div>
<p id="invitation-refresh-status" role="status"></p>
<div id="invitation-rows">
<?php if (!$invitations): ?><p class="member-empty muted"><?=tr_html('No invitations yet.')?></p><?php endif; ?>
<?php foreach ($invitations as $invite):
    $member=$invite['member'];
    $pending=$invite['status']==='pending';
    $fresh=$pending&&$invite['id']===$newInviteId;
    $inviteStatus=match($invite['status']) {
        'pending'=>tr('Awaiting acceptance'),'accepted'=>tr('Accepted'),'revoked'=>tr('Revoked'),
        'declined'=>tr('Declined'),default=>tr('Expired'),
    };
?>
<div class="invitation-entry <?=$fresh?'invitation-new':''?>">
<div class="member-line"><?php memberAvatar($member);?><div><strong><?=h($member)?></strong><small><?=h(libraryRoleLabel($invite['role']))?><?php if ($pending): ?> · <?=h(sprintf(tr('Expires %s UTC'),gmdate('Y-m-d',$invite['expires'])))?><?php endif; ?></small></div><span class="role-chip <?=$invite['status']==='accepted'?'role-owner':''?>"><?=h($inviteStatus)?></span></div>
<?php if ($pending): ?>
<div class="copy-row invitation-actions">
<label <?=$fresh?'':'hidden'?>><?=tr_html('Invitation URL')?><input class="share-link" readonly value="<?=h(invitationLink($library['id'],$invite['id']))?>"></label>
<button type="button" <?=$fresh?'class="primary"':''?> data-copy-url><?=icon('link')?><?=tr_html('Copy invitation link')?></button>
<small role="status" class="copy-result" data-copied="<?=tr_html('Copied.')?>" data-manual="<?=tr_html('Copy failed. Select and copy the link manually.')?>"></small>
<?php if ($owner||$invite['role']!=='admin'): ?><form method="post" action="up.php"><?php hidden($csrf,'member_cancel',$dir);?><input type="hidden" name="member" value="<?=h($member)?>"><input type="hidden" name="invitation_id" value="<?=h($invite['id'])?>"><button><?=tr_html('Cancel invitation')?></button></form><?php endif; ?>
</div>
<?php endif; ?></div>
<?php endforeach; ?></div></div>
</dialog>
<dialog id="invite-member-dialog" class="sheet manage-dialog role-dialog" aria-labelledby="invite-member-title" <?=$inviteError?'data-manage-open':''?>>
<div class="bar dialog-head"><h2 id="invite-member-title"><?=tr_html('Invite member')?></h2><button type="button" class="icon-button dialog-close" aria-label="<?=tr_html('Close')?>"><?=icon('close')?></button></div>
<p class="muted"><?=tr_html('Invite an existing account. Access starts after they accept.')?></p>
<p class="muted"><?=tr_html('No account yet? A site administrator can create one from Site accounts.')?></p>
<?php if ($inviteError): ?><p class="error" role="alert"><?=h($error)?></p><?php endif; ?>
<form method="post" action="up.php" class="role-form"><?php hidden($csrf,'member_invite',$dir);?>
<label class="member-name-input"><?=tr_html('Username')?><input name="member" value="<?=h($inviteError?$draftMember:'')?>" maxlength="32" required autocapitalize="none" autofocus></label>
<?php roleInputs($inviteError?$draftRole:'',$owner); ?>
<footer class="role-footer"><button class="primary"><?=tr_html('Send invitation')?></button></footer></form>
</dialog>
<dialog id="edit-role-dialog" class="sheet manage-dialog role-dialog" aria-labelledby="edit-role-title" <?=$editError?'data-manage-open':''?>>
<div class="bar dialog-head"><h2 id="edit-role-title"><?=tr_html('Change role')?></h2><button type="button" class="icon-button dialog-close" aria-label="<?=tr_html('Close')?>"><?=icon('close')?></button></div>
<p class="muted" data-current-member><?=h($editError?$draftMember:'')?></p>
<?php if ($editError): ?><p class="error" role="alert"><?=h($error)?></p><?php endif; ?>
<form method="post" action="up.php" class="role-form"><?php hidden($csrf,'member_edit',$dir);?><input type="hidden" name="member" value="<?=h($editError?$draftMember:'')?>">
<?php roleInputs($editError?$draftRole:'',$owner); ?>
<footer class="role-footer"><button class="primary"><?=tr_html('Save role')?></button></footer></form>
</dialog>
<?php endif; ?>
