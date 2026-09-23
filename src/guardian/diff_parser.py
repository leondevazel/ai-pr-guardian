from unidiff import PatchSet

from guardian.models import ChangedFile, Hunk, PRContext


def parse_diff(diff_text: str) -> PRContext:
    if not diff_text.strip():
        return PRContext()

    files = []
    for patched_file in PatchSet(diff_text):
        hunks = [
            Hunk(
                start_line=hunk.target_start,
                added_lines=[
                    (line.target_line_no, line.value.rstrip("\n"))
                    for line in hunk
                    if line.is_added
                ],
                removed_lines=[
                    (line.source_line_no, line.value.rstrip("\n"))
                    for line in hunk
                    if line.is_removed
                ],
                # Markers are kept. unidiff's line.value omits them, and joining bare values
                # produced a blob where deleted code read as if it still ran right before the
                # new code — which is what made agents report imaginary unreachable branches.
                context="".join(line.line_type + line.value for line in hunk),
            )
            for hunk in patched_file
        ]
        files.append(ChangedFile(path=patched_file.path, hunks=hunks))

    return PRContext(files=files)
