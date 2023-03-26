/**
* This is a secure disaggregated remote shared-memory system
* It's two fundmental aspects are confidentiality and integrity of data in remote DDR(NVM)
* We decouple the pool management and data management
* 1. For the confidentiality: we use CME which is consistent with existing research
* 2. For the integrity: We propose IncompleteIntegrityTree which is a space-friendly scheme
*    based on SGX-style integrity tree
*
* Following is the defination of secure remote memory structure
* v1.0: unable to dynamic extend
*/
#ifndef _SDM_HH_
#define _SDM_HH_

#include <stdint.h>

#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

/**
 * 约定
 * 1.远端内存的分配的粒度是页面(4K),传输粒度也应为4K以上
 * 2.T(integrity tree)的节点大小为64B(CacheLine)
 * 3.申请时本地[内存控制器(CXL扩展内存控制器)](-> 这里不太清楚是不是这样的)
 * 会对安全内存的申请做修改：
 *      1. 修改申请大小
 *      2. 在本地记录安全内存的metadata
 *      3. 对于相应的Root的管理,假设Root保证能在本地安全存储
*/
#define SDM_HMAC_ZOOM 128      // 缩放系数与选择的输入长度和hash算法有关
#define CL_SIZE 64            // 64B = 512 bit = CacheLine_Size
#define PAGE_SIZE 4096
#define CL_ALIGN_MASK   0xffffffffffffffC0// +by psj:CL mask错误
#define PAGE_ALIGN_MASK 0xfffffffffffff000// +by psj:PAGE mask错误
#define IIT_NODE_SIZE 64       // 64B = 512 bit = CacheLine_Size
#define IIT_HASHTAG_SIZE 7     // 7B = 56 bit
#define IIT_COUNTER_SIZE 7     // 7B = 56 bit
#define IIT_COUNTER_NUMS 8     //(CL_SIZE-IIT_HASHTAG_SIZE)/IIT_COUNTER_SIZE

typedef uint64_t Addr;       // 64位地址类型
typedef uint64_t iit_root;
typedef uint8_t* sdm_dataPtr;
typedef uint8_t* sdm_HMACPtr[CL_SIZE];
typedef uint64_t sdm_size;
typedef uint8_t  iit_node_hash_tag[IIT_HASHTAG_SIZE];
typedef uint8_t  iit_node_counter[IIT_COUNTER_SIZE];
/**
 * 这是HMAC结构
*/
typedef struct _sdm_hmac
{
    sdm_HMACPtr hmac;
    void print()
    {
        for (int i=0;i<CL_SIZE;i++)
            printf("%02x",hmac[i]);
        printf("\n");
    }
}sdm_hmac;
typedef sdm_hmac* sdm_hmacPtr;
/**
 * metadata结构如下
 * |metadata|
 * |         --------------------\
 * |                              ------------------\
 * |-数据空间大小-|-数据空间指针-|-HMAC指针-|-完整性树指针-|
*/
typedef struct _sdm_space
{
    private:
    uint64_t ceil(uint64_t a, uint64_t b)
    {
        return ((a/b) + (((a%b)==0)?0:1));
    }
    sdm_size  sDataSize; // 字节单位
    sdm_dataPtr dataPtr; // 数据区指针
    sdm_hmacPtr HMACPtr; // sizeof(HMAC)=sDataSize/sDMHMACZOOM
    iit_nodePtr  iITPtr; // 完整性树指针
    iit_root Root;       // 当前树Root

    /**
     * @author:yqy
     * @brief:根据传入的物理地址,读取缓存行对应的Counter
     * @attention:这里传入的是经过本地节点MMU转换后的"物理地址",函数会返回Counter的指针
    */
    iit_node_counter *getCounter(Addr paddr)
    {
        paddr &= CL_ALIGN_MASK;// 按缓存行对齐
        assert((Addr)dataPtr <= paddr && paddr <= (Addr)dataPtr + sDataSize - 1 && "invalid paddr in SDM");
        Addr base = (paddr-(Addr)dataPtr) / (CL_SIZE * IIT_COUNTER_NUMS);
        // 这个转换是为了与iit_node中取counter[k]的操作保持一致
        uint32_t offset = (((uint32_t)(paddr-(Addr)dataPtr))/(CL_SIZE)) % IIT_COUNTER_NUMS;//+by psj:node内counter值计算错误
        iit_nodePtr nodePtr = iITPtr + base;
        return nodePtr->getCounter_k(offset);
    }

    /**
     * @author:yqy
     * @brief:从第leaf_k个叶节点的第k个counter处开始向上校验
    */
    bool iit_verify(Addr paddr)
    {
        // 按缓存行对齐
        paddr &= CL_ALIGN_MASK;
        assert((Addr)dataPtr <= paddr && paddr <= (Addr)dataPtr + sDataSize - 1 && "invalid paddr in SDM");
        // 层内偏移, 0~7CLst => node[0], 8CLst => node[1]
        Addr curLeveloff = (paddr-(Addr)dataPtr) / (CL_SIZE * IIT_COUNTER_NUMS);

        // 节点内偏移, 这个转换(u32)是为了与iit_node中取counter[k]的操作保持一致
        uint32_t curCounteroff = ((uint32_t)(paddr-(Addr)dataPtr) / (CL_SIZE)) % IIT_COUNTER_NUMS;
        // 当前层节点数量 = 叶节点数量
        uint32_t curLevelNodeNum = sDataSize / (CL_SIZE * IIT_COUNTER_NUMS);
        // 当前层的起始地址
        iit_nodePtr curLevelNodeStart = iITPtr;
        // 当前节点  =  层的起始地址 + 层内偏移
        iit_nodePtr curNode = curLevelNodeStart + curLeveloff;
        // 当前计数器 = 当其前节点 + 节点内偏移
        uint32_t cur_k = curCounteroff;
        // 暂存当前节点的和
        iit_node_counter son;
        counter_init(son);  // 初始化, 置0
        // +by ys:初始化错误
        counter_sum(son,*(curNode->getCounter_k(cur_k)));// 便于后续代码统一

        /**
         * 这里采用验证到根, 后续需要实现”缓存命中“优化
         * 这里没有实现本地内存缓存，后续需要添加内存缓存(找到节点地址和缓存地址映射关系)
         *
        */
        while (curLevelNodeNum)
        {
            // 首先将子结点的counter和与对应父节点(当前节点)counter比较
            bool valid = counter_cmp(son, (uint8_t *)curNode->getCounter_k(cur_k));
            assert(valid && "iit iit_verify failed");
            /*
            * 这里对curNode进行hash_tag校验
            */
            // valid = XXXhash_verify(curNode);
            // assert(valid && "iit iit_verify failed");
            // 下面准备当前层counter和
            counter_init(son);
            curNode->sum(son);

            /**
             * 准备向上校验当前节点的父节点
            */
            // 上一层起始 = 当前层起始 + 当前层数量
            curLevelNodeStart = curLevelNodeStart + curLevelNodeNum;
            // 上层的的节点数量 = ceil(当前层节点数量/8)
            curLevelNodeNum = ceil(curLevelNodeNum, IIT_COUNTER_NUMS);
            // 父counter的节点内偏移
            cur_k = curLeveloff % IIT_COUNTER_NUMS;
            // 父counter的层内偏移 = floor(当前节点层内偏移/8)
            curLeveloff /= IIT_COUNTER_NUMS;
            // 父节点 = 上层起始 + 上层内偏移
            curNode = curLevelNodeStart + curLeveloff;
        }
        // 对根节点进行验证 因为节点大小为64B Root只存7B～8B
        assert(counter_cmp(son,(uint8_t *)(&Root)) && "iit iit_verify failed");
        return true;
    }
    /**
     * @author:yqy
     * @brief:根据传入的物理地址,读取指定缓存行
     * @attention:这里传入的是经过本地节点MMU转换后的"物理地址",函数会将明文数据写入给出的指针
    */
    bool ReadCL(Addr paddr, uint8_t *cipher)
    {
        assert((Addr)dataPtr <= paddr && paddr <= (Addr)dataPtr + sDataSize - 1 && "invalid paddr in SDM");
        // 取得counter指针
        uint8_t *ctr_ptr = (uint8_t *)getCounter(paddr);
        // 取得hmac
        sdm_hmacPtr hmac_ptr =  HMACPtr + (paddr-(Addr)dataPtr) / PAGE_SIZE;

        /*
        * 这里应该进行相应的解密操作...
        * Decrypt(cipher, paddr, ctr_ptr, );
        * 同时并行进行HMAC校验操作....
        * assert(HMAC_Verify(hmac_ptr) && “HMAC verification failed”);
        * 且与下面的IT验证并行完成....
        */

        // IT校验
        assert(iit_verify(paddr));
    }

    /**
     * @author:yqy
     * @brief:根据传入的物理地址,更新IT
     * @attention:这里采用eager_update, 后续可能需要进行优化
    */
    void iit_update(Addr paddr)
    {
        // 按缓存行对齐
        paddr &= CL_ALIGN_MASK;
        assert((Addr)dataPtr <= paddr && paddr <= (Addr)dataPtr + sDataSize - 1 && "invalid paddr in SDM");
        // 层内偏移, 0~7CLst => node[0], 8CLst => node[1]
        Addr curLeveloff = (paddr-(Addr)dataPtr) / (CL_SIZE * IIT_COUNTER_NUMS);

        // 节点内偏移, 这个转换(u32)是为了与iit_node中取counter[k]的操作保持一致
        uint32_t curCounteroff = ((uint32_t)(paddr-(Addr)dataPtr) / (CL_SIZE)) % IIT_COUNTER_NUMS;
        // 当前层节点数量 = 叶节点数量
        uint32_t curLevelNodeNum = sDataSize / (CL_SIZE * IIT_COUNTER_NUMS);
        // 当前层的起始地址
        iit_nodePtr curLevelNodeStart = iITPtr;
        // 当前节点  =  层的起始地址 + 层内偏移
        iit_nodePtr curNode = curLevelNodeStart + curLeveloff;
        // 当前计数器 = 当其前节点 + 节点内偏移
        uint32_t cur_k = curCounteroff;
        // 暂存当前节点的和
        iit_node_counter son;
        counter_init(son);  // 初始化, 置0
        curNode->sum(son);  // 便于后续代码统一

        /**
         * 这里采用eager_update
         * 这里没有实现本地内存缓存，后续需要添加内存缓存(找到节点地址和缓存地址映射关系)
         * 这里的写法是串行模拟, 并非实际情况(得到所有更新节点, 并行计算)
        */
        while (curLevelNodeNum)
        {
            // 首先将子结点的counter和与对应父节点(当前节点)counter比较
            bool valid = counter_cmp(son, (uint8_t *)curNode->getCounter_k(cur_k));
            assert(valid && "iit iit_verify failed");
            /*
            * 这里对curNode进行hash_tag校验
            */
            // valid = XXXhash_verity(curNode);
            // assert(valid && "iit iit_verify failed");

            /**
             * 校验通过后, 更新counter, 计算hash_tag
             * 先准备当前层counter和
            */
            counter_init(son);
            curNode->sum(son);
            // 更新counter
            curNode->inc_counter(cur_k);
            // 计算hash_tag
            // XXXhash_update(curNode)

            /**
             * 准备向上校验当前节点的父节点
            */
            // 上一层起始 = 当前层起始 + 当前层数量
            curLevelNodeStart = curLevelNodeStart + curLevelNodeNum;
            // 上层的的节点数量 = ceil(当前层节点数量/8)
            curLevelNodeNum = ceil(curLevelNodeNum, IIT_COUNTER_NUMS);
            // 父counter的节点内偏移
            cur_k = curLeveloff % IIT_COUNTER_NUMS;
            // 父counter的层内偏移 = floor(当前节点层内偏移/8)
            curLeveloff /= IIT_COUNTER_NUMS;
            // 父节点 = 上层起始 + 上层内偏移
            curNode = curLevelNodeStart + curLeveloff;
        }
        // 对根节点进行验证 因为节点大小为64B Root只存7B～8B
        assert(counter_cmp(son,(uint8_t *)(&Root)) && "iit iit_verify failed");
        // 更新Root
        Root++;
    }

    /**
     * @author:yqy
     * @brief:根据传入的物理地址,写入指定缓存行
     * @attention:这里传入的是经过本地节点MMU转换后的"物理地址",函数会将明文数据写入给出的指针
    */
    bool WriteCL(Addr paddr, uint8_t *plaint)
    {
        assert((Addr)dataPtr <= paddr && paddr <= (Addr)dataPtr + sDataSize - 1 && "invalid paddr in SDM");
        // 注意在写入之前需要校验且部分需要串行
        assert(iit_verify(paddr));
        // 这里对完整性树进行更新
        iit_update(paddr);

        // 取得counter指针
        uint8_t *ctr_ptr = (uint8_t *)getCounter(paddr);
        // 取得hmac指针
        sdm_hmacPtr hmac_ptr =  HMACPtr + (paddr-(Addr)dataPtr)/PAGE_SIZE;

        /*
        * 这里应该进行相应的加密操作...
        * Encrypt(plaint, paddr, ctr_ptr);
        * 串行进行HMAC更新操作....
        * HMAC_update(hmac_ptr, plaint);// 这里的plaint中的数据已经是密文
        */
    }
}sdm_space;
/**
 * @author:yqy
 * @brief:将7B(56 bit)计数器置为0
*/
void counter_init(iit_node_counter x)
{
    for (uint32_t i = 0;i<IIT_COUNTER_SIZE;i++){
        x[i]=0;
    }
}
/**
 * @author:yqy
 * @brief:计算[counter] a+b->a
*/
void counter_sum(iit_node_counter a,iit_node_counter b)
{
    uint8_t o,c=0;
    for (uint32_t i=0;i<IIT_COUNTER_SIZE;i++)
    {
        o = a[i]; //
        a[i]+=b[i];
        if (a[i] < o) o = 1;//下一位需要进位
        else o = 0;// 复用
        //+by ys:判断符号误写
        if (a[i] == 0xFF && c == 0x1)
        {
            assert(o == 0x0 && "carrier error");// 进位出错
            a[i] = 0x0;
            c = 0x1;
        }
        else a[i]++,c = o;
    }
    assert(c==0x0 && "Counter overflow");
}
/**
 * @author:yqy
 * @brief:比较计数器a和b
*/
bool counter_cmp(iit_node_counter a,iit_node_counter b)
{
    for (uint32_t i=0;i<IIT_COUNTER_SIZE;i++)
    {
        if (a[i]!=b[i]) return false;
    }
    return true;
}
/* IT节点
 * |node|
 * |-----\
 * |      -------------------------------\
 * |                                      --------------------------------------\
 * |----56----|--56--|--56--|--56--|--56--|--56--|--56--|--56--|--56--|----8-----|
 * |-hash_tag-|-ctr1-|-ctr2-|-ctr3-|-ctr4-|-ctr5-|-ctr6-|-ctr7-|-ctr8-|-reserved-|
 * */
typedef struct _iit_node
{
    iit_node_hash_tag htg;                      // hash_tag
    iit_node_counter  ctr[IIT_COUNTER_NUMS];    // counters[]
    uint8_t iit_node_bitmap;                    // reserved 可用作缓存标记或lazy update标记

    /**
     * @author:yqy
     * @brief:将当节点置为0
    */
    void init()
    {
        memset(htg, 0, sizeof(iit_node_hash_tag));
        memset(ctr, 0, sizeof(iit_node_counter) * IIT_COUNTER_NUMS);
        memset(&iit_node_bitmap, 0, sizeof(uint8_t));
    }
    /**
     * @author:yqy
     * @brief:给第k个56bit的计数器增加1
    */
    void inc_counter(uint32_t k)
    {
        assert(k>=1 && k<=IIT_COUNTER_NUMS && "invalid counter index");
        uint8_t* ctr_k =  (uint8_t *)(ctr+k-1);
        uint8_t p = 0;
        do{
            ctr_k[p]++;
            if (ctr_k[p]==0x0) p++;//cur byte overflow
            else break;
        }while (p<IIT_COUNTER_SIZE);//+by psj:counter的size数值错误
        assert(p<IIT_COUNTER_SIZE && "56 bit counter has been exhausted");
    }
    /**
     * @author:yqy
     * @brief:给第k个56bit的计数器增加1
    */
    void sum(iit_node_counter cont)
    {
        for (int i = 0; i<IIT_COUNTER_NUMS ;i++)
            counter_sum(cont, ctr[i]);
    }
    /**
     * @author:yqy
     * @brief:返回第k个计数器的指针
    */
    iit_node_counter *getCounter_k(uint32_t k)
    {
        assert(k>=0 && k<IIT_COUNTER_NUMS && "invalid counter index");
        return (ctr+k);
    }
    /**
     * @author:yqy
     * @brief:打印第k个计数器的16进制值
    */
    void print(uint32_t k)
    {
        assert(k>=1 && k<=IIT_COUNTER_NUMS && "invalid counter index");
        for (int j=6;j>=0;j--)
            printf("%02x",ctr[k-1][j]);
        printf("\n");
    }
}iit_node;
typedef iit_node* iit_nodePtr;
#endif
