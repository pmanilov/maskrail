// Modified in this fork: copy only the last displayed scan's masked texts from the sandbox.
import { Alert } from '@snack-uikit/alert';
import { ButtonFilled, ButtonOutline } from '@snack-uikit/button';
import { FieldSelect, FieldTextArea } from '@snack-uikit/fields';
import { CopySVG, PlaySVG } from '@snack-uikit/icons';
import { toaster } from '@snack-uikit/toaster';
import { Typography } from '@snack-uikit/typography';
import { useMemo, useState } from 'react';

import { ApiRequestError } from '@/api/client';
import { useDataTypes, useScan } from '@/api/hooks';
import type { ScanResponse } from '@/api/types';
import { Card } from '@/components/Card';
import { MaskChip } from '@/components/MaskedText';
import { PageHeader } from '@/components/PageHeader';
import { ScanResultPanel } from '@/components/ScanResultPanel';
import { DATA_TYPE, DATA_TYPE_NAME } from '@/domain/dataTypes';
import { t } from '@/i18n/strings';

import styles from './TesterPage.module.scss';

export function TesterPage() {
  const [text, setText] = useState('');
  const [dataTypes, setDataTypes] = useState<number[]>([]);
  // The last successful scan survives a failed one: on error the result stays
  // on screen below the error strip instead of vanishing.
  const [lastResult, setLastResult] = useState<ScanResponse | null>(null);
  const copyText = (lastResult?.masked_texts ?? []).join('\n');

  const dataTypesQuery = useDataTypes();
  const scan = useScan();

  const dataTypeLabels = useMemo(() => {
    const map = new Map<number, string>();
    for (const dt of dataTypesQuery.data ?? []) {
      map.set(Number(dt.data_type), dt.display_name || dt.name || DATA_TYPE_NAME[Number(dt.data_type)]);
    }
    return map;
  }, [dataTypesQuery.data]);

  const dtLabel = (id: number) => dataTypeLabels.get(id) ?? DATA_TYPE_NAME[id] ?? String(id);

  const dataTypeOptions = useMemo(
    () =>
      (dataTypesQuery.data ?? []).map((dt) => ({
        value: Number(dt.data_type),
        option: dt.display_name || dt.name || DATA_TYPE_NAME[Number(dt.data_type)] || String(dt.data_type),
      })),
    [dataTypesQuery.data],
  );

  const handleScan = () => {
    scan.mutate(
      {
        text,
        data_types: dataTypes.length ? dataTypes : undefined,
      },
      { onSuccess: (data) => setLastResult(data) },
    );
  };

  const handleCopyResult = async (): Promise<void> => {
    try {
      if (navigator.clipboard) {
        await navigator.clipboard.writeText(copyText);
      } else {
        // Plain HTTP may not expose the Clipboard API.
        const area = document.createElement('textarea');
        try {
          area.value = copyText;
          area.style.position = 'fixed';
          area.style.opacity = '0';
          document.body.appendChild(area);
          area.select();
          if (!document.execCommand('copy')) throw new Error('execCommand copy failed');
        } finally {
          area.remove();
        }
      }
      toaster.userAction.success({ label: t.tester.resultCopied });
    } catch {
      toaster.userAction.error({ label: t.tester.copyResultFailed });
    }
  };

  const errorMessage =
    scan.error instanceof ApiRequestError
      ? scan.error.details
        ? `${scan.error.message} — ${scan.error.details}`
        : scan.error.message
      : scan.error
        ? t.tester.scanError
        : null;

  return (
    <div className={styles.page}>
      <PageHeader title={t.tester.title} description={t.tester.description} />

      <div className={styles.grid}>
        <Card title={t.tester.input}>
          <div className={styles.form}>
            <div className={styles.samples}>
              <span className={styles.samplesLabel}>{t.tester.examplesLabel}</span>
              {t.tester.samples.map((sample) => (
                <button
                  key={sample.label}
                  type="button"
                  className={styles.sampleChip}
                  onClick={() => setText(sample.text)}
                >
                  {sample.label}
                </button>
              ))}
            </div>
            <div className={styles.monoArea}>
              <FieldTextArea
                value={text}
                onChange={setText}
                placeholder={t.tester.inputPlaceholder}
                minRows={8}
              />
            </div>
            <FieldSelect
              selection="multiple"
              label={t.tester.dataTypes}
              hint={t.tester.dataTypesHint}
              options={dataTypeOptions}
              value={dataTypes}
              onChange={(v) => setDataTypes((v ?? []).map(Number))}
              loading={dataTypesQuery.isLoading}
            />
            <div className={styles.actions}>
              <ButtonFilled
                label={t.tester.scan}
                icon={<PlaySVG />}
                onClick={handleScan}
                loading={scan.isPending}
                disabled={!text.trim()}
              />
            </div>
          </div>
        </Card>

        <Card
          title={t.tester.resultTitle}
          action={
            lastResult !== null && copyText.length > 0 ? (
              <ButtonOutline
                size="xs"
                appearance="neutral"
                icon={<CopySVG />}
                label={t.tester.copyResult}
                onClick={handleCopyResult}
              />
            ) : undefined
          }
        >
          {errorMessage && <Alert appearance="error" icon description={errorMessage} />}

          {lastResult ? (
            <>
              {errorMessage && (
                <Typography
                  family="sans"
                  purpose="body"
                  size="s"
                  tag="div"
                  className={styles.staleNote}
                >
                  {t.tester.staleResult}
                </Typography>
              )}
              <ScanResultPanel result={lastResult} dtLabel={dtLabel} />
            </>
          ) : (
            !errorMessage && (
              <div className={styles.empty}>
                <div className={styles.emptyChips} aria-hidden="true">
                  <MaskChip placeholder="<EMAIL_1>" dataType={DATA_TYPE.PERSONAL_DATA} />
                  <MaskChip placeholder="<API_KEY_1>" dataType={DATA_TYPE.API_KEYS} />
                </div>
                <Typography family="sans" purpose="body" size="m" tag="div" className={styles.emptyTitle}>
                  {t.tester.emptyTitle}
                </Typography>
                <Typography family="sans" purpose="body" size="s" tag="div" className={styles.emptyHint}>
                  {t.tester.emptyHint}
                </Typography>
              </div>
            )
          )}
        </Card>
      </div>
    </div>
  );
}
